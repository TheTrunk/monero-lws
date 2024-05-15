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

#include "client.h"

#include <boost/asio/coroutine.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <chrono>

#include "rpc/scanner/commands.h"
#include "rpc/scanner/connection.h"
#include "rpc/scanner/read_commands.h"
#include "rpc/scanner/server.h"
#include "rpc/scanner/write_commands.h"

namespace lws { namespace rpc { namespace scanner
{
  namespace
  {
    constexpr const std::chrono::seconds reconnect_interval{30};

    struct push_accounts_handler
    {
      using input = push_accounts;
      static bool handle(const std::shared_ptr<client_connection>& self, input msg); 
    };

    struct replace_accounts_handler
    {
      using input = replace_accounts;
      static bool handle(const std::shared_ptr<client_connection>& self, input msg); 
    };

    using command = bool(*)(const std::shared_ptr<client_connection>&);
  }

  struct client_connection : connection
  {
    rpc::scanner::client& parent_;
    boost::asio::steady_timer reconnect_timer_;
    std::size_t next_push_;

    explicit client_connection(rpc::scanner::client& parent)
      : connection(parent.context()),
        parent_(parent),
        reconnect_timer_(parent.context()),
        next_push_(0)
    {}

    //! \return Handlers for commands from server
    static const std::array<command, 2>& commands() noexcept
    {
      static constexpr const std::array<command, 2> value{{
        call<push_accounts_handler, client_connection>,
        call<replace_accounts_handler, client_connection>
      }};
      static_assert(push_accounts_handler::input::id() == 0);
      static_assert(replace_accounts_handler::input::id() == 1);
      return value;
    }

    const std::shared_ptr<client_connection>& conn() const noexcept { return parent_.conn_; }
    const std::string& pass() const noexcept { return parent_.pass_; }
    std::vector<std::shared_ptr<queue>>& local() noexcept
    {
      return parent_.local_;
    } 

    void cleanup()
    {
      base_cleanup();
      parent_.reconnect();
    }
  };

  namespace
  {
    bool push_accounts_handler::handle(const std::shared_ptr<client_connection>& self, input msg)
    {
      if (!self)
        return false;

      MINFO("Adding " << msg.users.size() << " new accounts to workload");

      std::size_t iterations = 0;
      for (std::size_t i = 0; !msg.users.empty() && i < self->local().size(); ++i, ++iterations)
      {
        const auto count = std::max(std::size_t(1), msg.users.size() / (self->local().size() - i));
        self->local()[(i + self->next_push_) % self->local().size()]->push_accounts(
          std::make_move_iterator(msg.users.begin()), std::make_move_iterator(msg.users.begin() + count)
        );
        msg.users.erase(msg.users.begin(), msg.users.begin() + count);
      }

      self->next_push_ += iterations;
      self->next_push_ %= self->local().size(); 
      return true;
    }

    bool replace_accounts_handler::handle(const std::shared_ptr<client_connection>& self, input msg)
    {
      if (!self)
        return false;

      MINFO("Received " << msg.users.size() << " accounts as new workload");
      for (std::size_t i = 0; !msg.users.empty() && i < self->local().size(); ++i)
      {
        const auto count = std::max(std::size_t(1), msg.users.size() / (self->local().size() - i));
        std::vector<lws::account> thread_users{
          std::make_move_iterator(msg.users.begin()),
          std::make_move_iterator(msg.users.begin() + count)
        };
        msg.users.erase(msg.users.begin(), msg.users.begin() + count);
        self->local()[i]->replace_accounts(std::move(thread_users));
      }
      self->next_push_ = 0;
      return true;
    }
    
    class connector : public boost::asio::coroutine
    {
      std::shared_ptr<client_connection> self_;
    public:
      explicit connector(std::shared_ptr<client_connection> self)
        : boost::asio::coroutine(),
          self_(std::move(self))
      {}

      void operator()(const boost::system::error_code& error = {})
      {
        if (!self_ || error == boost::asio::error::operation_aborted)
          return; // exiting

        BOOST_ASIO_CORO_REENTER(*this)
        {
          for (;;)
          {
            for (;;)
            {
              MINFO("Attempting connection to " << self_->remote_address());
              BOOST_ASIO_CORO_YIELD self_->sock_.async_connect(self_->parent_.server_address(), *this);
              if (error)
                MERROR("Connection attempt failed: " << error.message());
              else
                break;

              self_->reconnect_timer_.expires_from_now(reconnect_interval);
              BOOST_ASIO_CORO_YIELD self_->reconnect_timer_.async_wait(*this);
            }

            MINFO("Connection made to " << self_->remote_address());
            const auto threads = boost::numeric_cast<std::uint32_t>(self_->local().size());
            if (write_command(self_->conn(), initialize{self_->pass(), threads}))
              break;
          }
          read_commands<client_connection>{std::move(self_)};
        }
      }
    };
  } // anonymous

  client::client(const std::string& address, std::string pass, std::vector<std::shared_ptr<queue>> local)
    : context_(),
      conn_(nullptr),
      local_(std::move(local)),
      server_address_(rpc::scanner::server::get_endpoint(address)),
      pass_(std::move(pass))
  {
    reconnect();
  }

  client::~client()
  {}

  void client::reconnect()
  {
    conn_ = std::make_shared<client_connection>(*this);
    connector{conn_}();
  } 
}}} // lws // rpc // scanner
