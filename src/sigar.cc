/*
 * Copyright (c) 2004-2009 Hyperic, Inc.
 * Copyright (c) 2009 SpringSource, Inc.
 * Copyright (c) 2009-2010 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <atomic>
#include <chrono>
#include <functional>
#include <shared_mutex>
#include <system_error>

#ifdef WIN32
#include <process.h>
#endif

#include "sigar.h"
#include "sigar_private.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>

using sigar::logit;
using sigar::LogLevel;
using namespace std::string_view_literals;

// I don't want to include folly as the library is also used from various
// go projects, and all I really needed was a folly::Synchronized.
class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    void setCallback(
            sigar::LogLevel l,
            std::function<void(sigar::LogLevel, std::string_view)> cb) {
        std::unique_lock<std::shared_mutex> guard(lock);
        level = l;
        callback = std::move(cb);
    }

    void log(sigar::LogLevel l, std::string_view message) {
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
    std::atomic<sigar::LogLevel> level{sigar::LogLevel::Error};
    std::function<void(sigar::LogLevel, std::string_view)> callback;
};

SIGAR_PUBLIC_API
void sigar::set_log_callback(
        sigar::LogLevel level,
        std::function<void(sigar::LogLevel, std::string_view)> callback) {
    Logger::instance().setCallback(level, std::move(callback));
}

SIGAR_PUBLIC_API
void sigar::logit(sigar::LogLevel level, std::string_view message) {
    Logger::instance().log(level, message);
}

static int execute_and_catch_exceptions(std::function<int()> function,
                                        std::string_view method) {
    logit(LogLevel::Debug, method);
    std::string message;
    int ret = EINVAL;

    try {
        ret = function();
        if (ret != SIGAR_OK) {
            logit(LogLevel::Debug,
                  fmt::format("{} returned error {}", method, ret));
        }
        return ret;
    } catch (const std::bad_alloc&) {
        message = "No memory";
        ret = ENOMEM;
    } catch (const std::system_error& ex) {
        message = ex.what();
        ret = ex.code().value();
    } catch (const std::exception& ex) {
        message = ex.what();
        ret = EINVAL;
    } catch (...) {
        message = "Unknown exception";
        ret = EINVAL;
    }

    logit(sigar::LogLevel::Error,
          fmt::format("{}: failed due to {}", method, message));
    return ret;
}

SIGAR_DECLARE(int) sigar_open(sigar_t** sigar) {
    return execute_and_catch_exceptions(
            [&sigar]() {
                *sigar = sigar_t::New();
                return SIGAR_OK;
            },
            "sigar_open"sv);
}

SIGAR_DECLARE(int) sigar_close(sigar_t* sigar) {
    delete sigar;
    return SIGAR_OK;
}

SIGAR_DECLARE(sigar_pid_t) sigar_pid_get(sigar_t* sigar) {
    // There isn't much point of trying to cache the pid (it would break
    // if the paren't ever called fork()). We don't use the variable
    // internally, and if the caller don't want the overhead of a system
    // call they can always cache it themselves
    return getpid();
}

SIGAR_DECLARE(int) sigar_mem_get(sigar_t* sigar, sigar_mem_t* mem) {
    if (!sigar || !mem) {
        return EINVAL;
    }
    *mem = {};
    return execute_and_catch_exceptions(
            [&sigar, &mem]() { return sigar->get_memory(*mem); },
            "sigar_mem_get"sv);
}

SIGAR_DECLARE(int) sigar_swap_get(sigar_t* sigar, sigar_swap_t* swap) {
    if (!sigar || !swap) {
        return EINVAL;
    }

    swap->total = SIGAR_FIELD_NOTIMPL;
    swap->used = SIGAR_FIELD_NOTIMPL;
    swap->free = SIGAR_FIELD_NOTIMPL;
    swap->page_in = SIGAR_FIELD_NOTIMPL;
    swap->page_out = SIGAR_FIELD_NOTIMPL;
    swap->allocstall = SIGAR_FIELD_NOTIMPL;
    swap->allocstall_dma = SIGAR_FIELD_NOTIMPL;
    swap->allocstall_dma32 = SIGAR_FIELD_NOTIMPL;
    swap->allocstall_normal = SIGAR_FIELD_NOTIMPL;
    swap->allocstall_movable = SIGAR_FIELD_NOTIMPL;

    return execute_and_catch_exceptions(
            [&sigar, &swap]() { return sigar->get_swap(*swap); },
            "sigar_swap_get"sv);
}

SIGAR_DECLARE(int) sigar_cpu_get(sigar_t* sigar, sigar_cpu_t* cpu) {
    if (!sigar || !cpu) {
        return EINVAL;
    }

#if 0
    // The correct thing to do would be to initialize to not impl, as
    // linux is the only platform adding some of these fields, but
    // it looks like people don't check if they're implemented or not
    cpu->user = SIGAR_FIELD_NOTIMPL;
    cpu->sys = SIGAR_FIELD_NOTIMPL;
    cpu->nice = SIGAR_FIELD_NOTIMPL;
    cpu->idle = SIGAR_FIELD_NOTIMPL;
    cpu->wait = SIGAR_FIELD_NOTIMPL;
    cpu->irq = SIGAR_FIELD_NOTIMPL;
    cpu->soft_irq = SIGAR_FIELD_NOTIMPL;
    cpu->stolen = SIGAR_FIELD_NOTIMPL;
    cpu->total = SIGAR_FIELD_NOTIMPL;
#endif
    *cpu = {};

    return execute_and_catch_exceptions(
            [&sigar, &cpu]() { return sigar->get_cpu(*cpu); },
            "sigar_cpu_get"sv);
}

static uint64_t sigar_time_now_millis() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
                   now.time_since_epoch())
            .count();
}

int sigar_t::get_proc_cpu(sigar_pid_t pid, sigar_proc_cpu_t& proccpu) {
    const auto time_now = sigar_time_now_millis();
    sigar_proc_cpu_t prev = {};
    auto iter = process_cache.find(pid);
    const bool found = iter != process_cache.end();
    if (found) {
        prev = iter->second;
    }

    auto status = get_proc_time(pid, *(sigar_proc_time_t*)&proccpu);
    if (status != SIGAR_OK) {
        if (found) {
            process_cache.erase(iter);
        }
        return status;
    }

    proccpu.last_time = time_now;
    if (!found || (prev.start_time != proccpu.start_time)) {
        // This is a new process or a different process we have in the cache
        process_cache[pid] = proccpu;
        return SIGAR_OK;
    }

    auto time_diff = time_now - prev.last_time;
    if (!time_diff) {
        // we don't want divide by zero
        time_diff = 1;
    }
    proccpu.percent = (proccpu.total - prev.total) / (double)time_diff;
    process_cache[pid] = proccpu;

    return SIGAR_OK;
}

SIGAR_DECLARE(int)
sigar_proc_mem_get(sigar_t* sigar, sigar_pid_t pid, sigar_proc_mem_t* procmem) {
    if (!sigar || !procmem) {
        return EINVAL;
    }

    procmem->size = SIGAR_FIELD_NOTIMPL;
    procmem->resident = SIGAR_FIELD_NOTIMPL;
    procmem->share = SIGAR_FIELD_NOTIMPL;
    procmem->minor_faults = SIGAR_FIELD_NOTIMPL;
    procmem->major_faults = SIGAR_FIELD_NOTIMPL;
    procmem->page_faults = SIGAR_FIELD_NOTIMPL;

    return execute_and_catch_exceptions(
            [&sigar, pid, &procmem]() {
                return sigar->get_proc_memory(pid, *procmem);
            },
            fmt::format("sigar_proc_mem_get({})", pid));
}

SIGAR_DECLARE(int)
sigar_proc_cpu_get(sigar_t* sigar, sigar_pid_t pid, sigar_proc_cpu_t* proccpu) {
    if (!sigar || !proccpu) {
        return EINVAL;
    }
    *proccpu = {};

    return execute_and_catch_exceptions(
            [&sigar, pid, &proccpu]() {
                return sigar->get_proc_cpu(pid, *proccpu);
            },
            fmt::format("sigar_proc_cpu_get({})", pid));
}

SIGAR_DECLARE(int)
sigar_proc_state_get(sigar_t* sigar,
                     sigar_pid_t pid,
                     sigar_proc_state_t* procstate) {
    if (!sigar || !procstate) {
        return EINVAL;
    }

    *procstate = {};
    procstate->tty = SIGAR_FIELD_NOTIMPL;
    procstate->nice = SIGAR_FIELD_NOTIMPL;
    procstate->threads = SIGAR_FIELD_NOTIMPL;
    procstate->processor = SIGAR_FIELD_NOTIMPL;

    return execute_and_catch_exceptions(
            [&sigar, pid, &procstate]() {
                return sigar->get_proc_state(pid, *procstate);
            },
            fmt::format("sigar_proc_state_get({})", pid));
}

SIGAR_PUBLIC_API
void sigar::iterate_child_processes(sigar_t* sigar,
                                    sigar_pid_t pid,
                                    IterateChildProcessCallback callback) {
    sigar->iterate_child_processes(pid, callback);
}
