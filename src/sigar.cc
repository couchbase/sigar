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

#include <stdio.h>
#include <chrono>
#include <system_error>
#ifdef WIN32
#include <process.h>
#endif

#include "sigar.h"
#include "sigar_private.h"

SIGAR_DECLARE(int) sigar_open(sigar_t** sigar) {
    try {
        *sigar = sigar_t::New();
        return SIGAR_OK;
    } catch (const std::bad_alloc&) {
        return ENOMEM;
    } catch (const std::system_error& ex) {
        return ex.code().value();
    } catch (...) {
        return EINVAL;
    }
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
    try {
        return sigar->get_memory(*mem);
    } catch (const std::bad_alloc&) {
        return ENOMEM;
    } catch (const std::system_error& ex) {
        return ex.code().value();
    } catch (...) {
        return EINVAL;
    }
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

    try {
        return sigar->get_swap(*swap);
    } catch (const std::bad_alloc&) {
        return ENOMEM;
    } catch (const std::system_error& ex) {
        return ex.code().value();
    } catch (...) {
        return EINVAL;
    }
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

    try {
        return sigar->get_cpu(*cpu);
    } catch (const std::bad_alloc&) {
        return ENOMEM;
    } catch (const std::system_error& ex) {
        return ex.code().value();
    } catch (...) {
        return EINVAL;
    }
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

    try {
        return sigar->get_proc_memory(pid, *procmem);
    } catch (const std::bad_alloc&) {
        return ENOMEM;
    } catch (const std::system_error& ex) {
        return ex.code().value();
    } catch (...) {
        return EINVAL;
    }
}

SIGAR_DECLARE(int)
sigar_proc_cpu_get(sigar_t* sigar, sigar_pid_t pid, sigar_proc_cpu_t* proccpu) {
    if (!sigar || !proccpu) {
        return EINVAL;
    }
    *proccpu = {};

    try {
        return sigar->get_proc_cpu(pid, *proccpu);
    } catch (const std::bad_alloc&) {
        return ENOMEM;
    } catch (const std::system_error& ex) {
        return ex.code().value();
    } catch (...) {
        return EINVAL;
    }
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

    try {
        return sigar->get_proc_state(pid, *procstate);
    } catch (const std::bad_alloc&) {
        return ENOMEM;
    } catch (const std::system_error& ex) {
        return ex.code().value();
    } catch (...) {
        return EINVAL;
    }
}

SIGAR_PUBLIC_API
void sigar::iterate_child_processes(sigar_t* sigar,
                                    sigar_pid_t pid,
                                    IterateChildProcessCallback callback) {
    sigar->iterate_child_processes(pid, callback);
}
