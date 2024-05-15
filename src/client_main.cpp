// Copyright (c) 2024, The Monero Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <boost/optional/optional.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/thread/thread.hpp>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/command_line.h" // monero/src/
#include "common/expect.h"       // monero/src/
#include "common/util.h"         // monero/src/
#include "config.h"
#include "cryptonote_config.h"   // monero/src/
#include "db/storage.h"
#include "error.h"
#include "options.h"
#include "rpc/scanner/client.h"
#include "scanner.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "lws"

namespace
{
  struct options
  {
    const command_line::arg_descriptor<std::string> config_file;
    const command_line::arg_descriptor<std::string> log_level;
    const command_line::arg_descriptor<std::string> lws_daemon;
    const command_line::arg_descriptor<std::string> lws_pass;
    const command_line::arg_descriptor<std::string> monerod_rpc;
    const command_line::arg_descriptor<std::string> network;
    const command_line::arg_descriptor<std::string> scan_threads;

    options()
      : config_file{"config-file", "Specify any option in a config file; <name>=<value> on separate lines"}
      , log_level{"log-level", "Log level [0-4]", 1}
      , lws_daemon{"lws-daemon", "Specify monero-lws-daemon main process <tcp://[ip:]port>", ""}
      , lws_pass{"lws-pass", "Specify monero-lws-daemon password", ""}
      , monerod_rpc{"monerod-rpc", "Specify monero ZMQ RPC server <tcp://ip:port> or <ipc:///path>", ""}
      , network{"network", "<\"main\"|\"stage\"|\"test\"> - Blockchain net type", "main"}
      , scan_threads{"scan-threads", "Number of scan threads", boost::thread::hardware_concurrency()}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      command_line::add_arg(description, config_file);
      command_line::add_arg(description, log_level);
      command_line::add_arg(description, lws_daemon);
      command_line::add_arg(description, lws_pass);
      command_line::add_arg(description, monerod_rpc);
      command_line::add_arg(description, network);
      command_line::add_arg(description, command_line::arg_help);
    }

    void set_network(boost::program_options::variables_map const& args) const
    {
      const std::string net = command_line::get_arg(args, network);
      if (net == "main")
        lws::config::network = cryptonote::MAINNET;
      else if (net == "stage")
        lws::config::network = cryptonote::STAGENET;
      else if (net == "test")
        lws::config::network = cryptonote::TESTNET;
      else
        throw std::runtime_error{"Bad --network value"};
    }
  };

  struct program
  {
    std::string lws_daemon;
    std::string lws_pass;
    std::string monerod_rpc;
    std::size_t scan_threads;    
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options]" << std::endl;
    out << description;
  }

  boost::optional<program> get_program(int argc, char** argv)
  {
    namespace po = boost::program_options;

    const options opts{};
    po::variables_map args{};
    {
      po::options_description description{"Options"};
      opts.prepare(description);

      po::store(
        po::command_line_parser(argc, argv).options(description).run(), args
      );
      po::notify(args);

      if (!command_line::is_arg_defaulted(args, opts.config_file))
      {
        boost::filesystem::path config_path{command_line::get_arg(args, opts.config_file)};
        if (!boost::filesystem::exists(config_path))
          MONERO_THROW(lws::error::configuration, "Config file does not exist");

        po::store(
          po::parse_config_file<char>(config_path.string<std::string>().c_str(), description), args
        );
        po::notify(args);
      }
    }

    if (command_line::get_arg(args, command_line::arg_help))
    {
      print_help(std::cout);
      return boost::none;
    }

    opts.set_network(args); // do this first, sets global variable :/
    mlog_set_log_level(command_line::get_arg(args, opts.log_level));

    program prog{
      command_line::get_arg(args, opts.lws_daemon),
      command_line::get_arg(args, opts.lws_pass),
      command_line::get_arg(args, opts.monerod_rpc),
      command_line::get_arg(args, opts.scan_threads)
    };
    prog.scan_threads = std::max(std::size_t(1), prog.scan_threads);
    return prog;
  }

  void run(program prog)
  {
    std::signal(SIGINT, [] (int) { lws::scanner::stop(); });

    auto ctx = lws::rpc::context::make(std::move(prog.monerod_rpc), std::move(prog.monerod_sub), {}, {}, std::chrono::minutes{0}, false);

    MINFO("Using monerod ZMQ RPC at " << prog.monerod);

    rpc::scanner::client client{};

    // blocks until SIGINT
    lws::scanner::run(std::move(disk), std::move(ctx), prog.scan_threads, webhook_verify, enable_subaddresses, prog.untrusted_daemon);
  }


} // anonymous

int main(int argc, char** argv)
{
  tools::on_startup(); // if it throws, don't use MERROR just print default msg

  try
  {
    boost::optional<program> prog;

    try
    {
      prog = get_program(argc, argv);
    }
    catch (std::exception const& e)
    {
      std::cerr << e.what() << std::endl << std::endl;
      print_help(std::cerr);
      return EXIT_FAILURE;
    }

    if (prog)
      run(std::move(*prog));
  }
  catch (std::exception const& e)
  {
    MERROR(e.what());
    return EXIT_FAILURE;
  }
  catch (...)
  {
    MERROR("Unknown exception");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;

}
