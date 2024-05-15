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

#include "server.h"

#include <boost/asio/coroutine.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <vector>
#include "byte_slice.h"  // monero/contrib/epee/include
#include "byte_stream.h" // monero/contrib/epee/include
#include "error.h"
#include "rpc/scanner/commands.h"
#include "rpc/scanner/connection.h"
#include "rpc/scanner/read_commands.h"
#include "rpc/scanner/write_commands.h"
#include "scanner.h"

namespace lws { namespace rpc { namespace scanner
{
  namespace
  {
    /*! \brief Only way to immediately return from io_service post/run call.
      Error handling is as follows in this file:
        - Error local to remote endpoint - use bool return
        - Recoverable blockchain or account state issue - throw `reset_state`
        - Unrecoverable error - throw hard exception (close process). */
    struct reset_state : std::exception
    {
      reset_state() :
        std::exception()
      {}

      virtual const char* what() const noexcept override
      { return "reset_state / abort scan"; }
    };

    //! \brief Handler for server to initialize new scanner
    struct initialize_handler
    {
      using input = initialize;
      static bool handle(const std::shared_ptr<server_connection>& self, input msg);
    };

    //! \brief Handler for request to update accounts
    struct update_accounts_handler
    {
      using input = update_accounts;
      static bool handle(const std::shared_ptr<server_connection>& self, input msg);
    };

    using command = bool(*)(const std::shared_ptr<server_connection>&);
  } // anonymous

  //! \brief Context/state for remote `monero-lws-scanner` instance.
  struct server_connection : connection
  {
    server& parent_;
    db::storage disk_;
    rpc::client zclient_;
    std::uint32_t threads_; //!< Number of scan threads at remote process
    const ssl_verification_t webhook_verify_;

    explicit server_connection(server& parent)
      : connection(parent.context_),
        parent_(parent),
        disk_(parent.disk_.clone()),
        zclient_(MONERO_UNWRAP(parent.zclient_.clone())),
        threads_(0),
        webhook_verify_(parent.webhook_verify_)
    {
      MINFO("New scanner client at " << remote_address());
    }

    //! \return Handlers for commands from client
    static const std::array<command, 2>& commands() noexcept
    {
      static constexpr const std::array<command, 2> value{{
        call<initialize_handler, server_connection>,
        call<update_accounts_handler, server_connection>
      }};
      static_assert(initialize_handler::input::id() == 0);
      static_assert(update_accounts_handler::input::id() == 1);
      return value;
    }

    bool check_pass(const std::string& pass)
    {
      return pass == parent_.pass_;
    }

    bool replace_users()
    {
      return parent_.replace_users();
    }

    //! Cancels pending operations and "pushes" accounts to other processes
    void cleanup()
    {
      base_cleanup();
    }
  };

  namespace
  {
    bool initialize_handler::handle(const std::shared_ptr<server_connection>& self, const input msg)
    {
      if (!self)
        return false;

      if (self->threads_)
      {
        MERROR("Client ( " << self->remote_address() << ") invoked initialize twice, closing connection");
        return false;
      }

      if (!msg.threads)
      {
        MERROR("Client (" << self->remote_address() << ") intialized with 0 threads");
        return false;
      }

      if (!self->check_pass(msg.pass))
      {
        MERROR("Client (" << self->remote_address() << ") provided invalid pass");
        return false;
      }

      self->threads_ = msg.threads;
      if (self->replace_users())
      {
        MINFO("Initialization from remote scanner (" << self->remote_address() << ") - " << msg.threads << " thread(s)");
        return true;
      }
      else
        MERROR("Failed new initialization from remote scanner (" << self->remote_address() << ')');
      return false;
    }

    bool update_accounts_handler::handle(const std::shared_ptr<server_connection>& self, input msg)
    {
      static constexpr const scanner_options opts{
        epee::net_utils::ssl_verification_t::system_ca, false, false
      };
 
      std::sort(msg.users.begin(), msg.users.end(), by_height{});
      if (!user_data::store(self->disk_, self->zclient_, epee::to_span(msg.blocks), epee::to_span(msg.users), nullptr, opts))
        throw reset_state();
      return true;
    }
  } // anonymous

  class server::acceptor : public boost::asio::coroutine
  {
    server* self_;
    std::shared_ptr<server_connection> next_;

  public:
    explicit acceptor(server& self)
      : boost::asio::coroutine(), self_(std::addressof(self)), next_(nullptr)
    {}

    void operator()(const boost::system::error_code& error = {})
    {
      if (!self_ || error)
      {
        if (error == boost::asio::error::operation_aborted)
          return; // exiting
        MONERO_THROW(error, "server acceptor failed");
      }
      BOOST_ASIO_CORO_REENTER(*this)
      {
        for (;;)
        {
          next_ = std::make_shared<server_connection>(*self_);
          BOOST_ASIO_CORO_YIELD self_->acceptor_.async_accept(next_->sock_, *this);

          // delay enable_pull_accounts until async_accept completes
          MONERO_UNWRAP(next_->zclient_.enable_pull_accounts());
          self_->remote_.emplace(next_);
          read_commands<server_connection>{std::move(next_)}();
        }
      }
    }
  };

  boost::asio::ip::tcp::endpoint server::get_endpoint(const std::string& address)
  {
    std::string host;
    std::string port;
    {
      const auto split = address.rfind(':');
      if (split == std::string::npos)
      {
        host = "0.0.0.0";
        port = address;
      }
      else
      {
        host = address.substr(0, split);
        port = address.substr(split + 1);
      }
    }
    return boost::asio::ip::tcp::endpoint{
      boost::asio::ip::address::from_string(host), boost::lexical_cast<unsigned short>(port)
    };
  }

  server::server(const std::string& address, std::string pass, db::storage disk, rpc::client zclient, ssl_verification_t webhook_verify)
    : context_(),
      acceptor_(context_),
      remote_(),
      disk_(std::move(disk)),
      zclient_(std::move(zclient)),
      pass_(std::move(pass)),
      webhook_verify_(webhook_verify)
  {
    const auto endpoint = get_endpoint(address); 
    acceptor_.open(endpoint.protocol());
    acceptor_.bind(endpoint);
    acceptor_.listen();

    acceptor{*this}();
  }

  server::~server() noexcept
  {}

  bool server::replace_users()
  { 
    std::size_t total_threads = local_.size();
    std::vector<std::shared_ptr<server_connection>> remotes;
    remotes.reserve(remote_.size());
    for (const auto& conn : remote_)
    {
      auto conn_shared = conn.lock();
      if (conn_shared)
      {
        if (std::numeric_limits<std::size_t>::max() - total_threads < conn_shared->threads_)
        {
          MERROR("Exceeded max threads (size_t), cancelling new remote scanner initialization");
          return false;
        }

        total_threads += conn_shared->threads_;
        remotes.push_back(std::move(conn_shared));
      }
    }

    std::vector<lws::account> users{};
    auto reader = MONERO_UNWRAP(disk_.start_read());
    auto active_users = MONERO_UNWRAP(reader.get_accounts(db::account_status::active));
    auto total_users = active_users.count();
    auto users_it = active_users.make_iterator();

    for (std::size_t i = 0; !users_it.is_end() && i < local_.size(); ++i)
    {
      const auto this_users = std::max(std::size_t(1), total_users / total_threads);
      users.reserve(this_users);

      for (std::size_t j = 0; !users_it.is_end() && j < this_users; ++j, ++users_it)
      {
        users.push_back(
          MONERO_UNWRAP(reader.get_full_account(users_it.get_value<db::account>()))
        );
      }

      local_[i]->replace_accounts(std::move(users));
      users.clear();
      --total_threads;
      total_users -= this_users;
    }

    active_users.reset();
    users_it = active_users.make_iterator();

    for (std::size_t i = 0; !users_it.is_end() && i < remotes.size(); ++i)
    {
      const auto this_threads = remotes[i]->threads_;
      const auto this_users = std::max(std::size_t(1), total_users / (total_threads / this_threads));
      users.reserve(this_users);

      for (std::size_t j = 0; !users_it.is_end() && j < this_users; ++j, ++users_it)
      {
        users.push_back(
          MONERO_UNWRAP(reader.get_full_account(users_it.get_value<db::account>()))
        );
      }

      if (!write_command(remotes[i], replace_accounts{std::move(users)}))
        return false;
      users.clear();
      total_threads -= this_threads;
      total_users -= this_users;
    }

    return true;
  }

  expect<void> server::poll_io()
  {
    try
    {
      // a bit inefficient, but I don't want an aggressive scanner blocking this
      for (unsigned i = 0 ; i < 1000; ++i)
      { 
        context_.reset();
        if (!context_.poll_one())
          break;
      }
    }
    catch (const reset_state&)
    {
      return {error::signal_abort_scan};
    }

    bool replace = false;
    for (auto conn = remote_.begin(); conn != remote_.end(); )
    {
      auto shared = conn->lock();
      if (!shared)
      {
        replace = true;
        conn = remote_.erase(conn);
      }
      else
        ++conn;
    }
    if (replace && !replace_users())
      throw std::runtime_error{"Failed replace_users call"};
    return success();
  }
}}} // lws // rpc // scanner
