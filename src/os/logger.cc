/*
 *     Copyright 2023-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include <sigar/logger.h>
#include <atomic>
#include <mutex>
#include <shared_mutex>

using sigar::logit;
using namespace std::string_view_literals;

// I don't want to include folly as the library is also used from various
// go projects, and all I really needed was a folly::Synchronized.
class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    void setCallback(int l, std::function<void(int, std::string_view)> cb) {
        std::unique_lock<std::shared_mutex> guard(lock);
        level = l;
        callback = std::move(cb);
    }

    void log(int l, std::string_view message) {
        if (l < level) {
            return;
        }
        std::shared_lock<std::shared_mutex> guard(lock);
        if (callback && l >= level) {
            callback(l, message);
        }
    }

protected:
    std::shared_mutex lock;
    std::atomic<int> level{std::numeric_limits<int>::max()};
    std::function<void(int, std::string_view)> callback;
};

void sigar::set_log_callback(
        int level, std::function<void(int, std::string_view)> callback) {
    Logger::instance().setCallback(level, std::move(callback));
}

void sigar::logit(int level, std::string_view message) {
    Logger::instance().log(level, message);
}
