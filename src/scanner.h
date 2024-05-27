// Copyright (c) 2018-2020, The Monero Project
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
#pragma once

#include <atomic>
#include <boost/optional/optional.hpp>
#include <cstdint>
#include <string>

#include "db/fwd.h"
#include "db/storage.h"
#include "net/net_ssl.h" // monero/contrib/epee/include
#include "rpc/client.h"
#include "rpc/scanner/fwd.h"
#include "span.h"        // monero/contrib/epee/include

namespace lws
{
  struct scanner_options
  {
    epee::net_utils::ssl_verification_t webhook_verify;
    bool enable_subaddresses;
    bool untrusted_daemon;
  };

  //! Used in `scan_loop` by server
  class user_data
  {
    db::storage disk_;

  public:
    user_data(db::storage disk)
      : disk_(std::move(disk))
    {}

    user_data(user_data const& rhs)
      : disk_(rhs.disk_.clone())
    {}

    user_data(user_data&& rhs)
      : disk_(std::move(rhs.disk_))
    {}

    /*! Store updated accounts locally (`disk`), and send ZMQ/RMQ/webhook
      events. `users` must be sorted by height (lowest first). */
    static bool store(db::storage& disk, rpc::client& zclient, epee::span<const crypto::hash> chain, epee::span<const lws::account> users, epee::span<const db::pow_sync> pow, const scanner_options&);

    //! `users` must be sorted by height (lowest first)
    bool operator()(rpc::client& zclient, epee::span<const crypto::hash> chain, epee::span<const lws::account> users, epee::span<const db::pow_sync> pow, const scanner_options&);
  };

  //! Scans all active `db::account`s. Detects if another process changes active list.
  class scanner
  {
    static std::atomic<bool> running;

    scanner() = delete;

  public:

    //! Callback for storing user account (typically local lmdb, but perhaps remote rpc)
    using store_func = std::function<bool(rpc::client&, epee::span<const crypto::hash>, epee::span<const lws::account>, epee::span<const db::pow_sync>, const scanner_options&)>;

    /*! Run _just_ the inner scanner loop. Calls `store` on account updates.
      \throw std::exception on hard errors (shutdown) conditions
      \return True iff `queue` indicates thread now has zero accounts. False
        indictes a soft, typically recoverable error. */
    static bool loop(std::atomic<bool>& stop, store_func store, std::optional<db::storage> disk, rpc::client client, std::vector<lws::account> users, rpc::scanner::queue& queue, const scanner_options& opts, bool leader_thread); 
    
    //! Use `client` to sync blockchain data, and \return client if successful.
    static expect<rpc::client> sync(db::storage disk, rpc::client client, const bool untrusted_daemon = false);

    //! Poll daemon until `stop()` is called, using `thread_count` threads.
    static void run(db::storage disk, rpc::context ctx, std::size_t thread_count, const std::string& server_addr, std::string server_pass, const scanner_options&);

    //! \return True if `stop()` has never been called.
    static bool is_running() noexcept { return running; }

    //! Stops all scanner instances globally.
    static void stop() noexcept { running = false; }

    //! For testing, \post is_running() == true
    static void reset() noexcept { running = true; }
  };
} // lws
