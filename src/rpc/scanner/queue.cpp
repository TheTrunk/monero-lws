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

#include "queue.h"

#include "db/account.h"
#include "scanner.h"

namespace lws { namespace rpc { namespace scanner 
{
  queue::status queue::do_get_accounts()
  {
    status out{
     std::move(replace_), std::move(push_), user_count_
    };
    replace_ = std::nullopt;
    push_.clear();
    push_.shrink_to_fit();
    return out; 
  }

  queue::~queue()
  {}

  std::size_t queue::user_count()
  {
    const boost::lock_guard<boost::mutex> lock{sync_};
    return user_count_;
  }

  queue::status queue::get_accounts()
  {
    const boost::lock_guard<boost::mutex> lock{sync_};
    return do_get_accounts();
  }

  queue::status queue::wait_for_accounts(std::atomic<bool>& stop)
  {
    boost::unique_lock<boost::mutex> lock{sync_};
    if (!replace_ && push_.empty())
      poll_.wait(lock, [this, &stop] () { return replace_ || !push_.empty() || !stop; });
    return do_get_accounts();
  }

  void queue::replace_accounts(std::vector<lws::account> users)
  {
    {
      const boost::lock_guard<boost::mutex> lock{sync_};
      replace_ = std::move(users);
      user_count_ = replace_->size();
      push_.clear();
    }
    poll_.notify_all();
  }
}}} // lws // rpc // scanner
