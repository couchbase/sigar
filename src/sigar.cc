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
#include <system_error>
#ifdef WIN32
#include <process.h>
#endif

#include "sigar.h"
#include "sigar_private.h"
#include "sigar_util.h"

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

SIGAR_DECLARE(int) sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap) {
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

/* XXX: add clear() function */
/* XXX: check for stale-ness using start_time */
int sigar_t::get_proc_cpu(sigar_pid_t pid, sigar_proc_cpu_t& proccpu) {
    sigar_cache_entry_t* entry;
    sigar_proc_cpu_t* prev;
    uint64_t otime, time_now = sigar_time_now_millis();
    uint64_t time_diff, total_diff;
    int status;

    if (!proc_cpu) {
        proc_cpu = sigar_cache_new(128);
    }

    entry = sigar_cache_get(proc_cpu, pid);
    if (entry->value) {
        prev = (sigar_proc_cpu_t*)entry->value;
    } else {
        prev = static_cast<sigar_proc_cpu_t*>(entry->value =
                                                      malloc(sizeof(*prev)));
        SIGAR_ZERO(prev);
    }

    time_diff = time_now - prev->last_time;
    proccpu.last_time = time_now;

    if (time_diff < 1000) {
        /* we were just called within < 1 second ago. */
        proccpu = *prev;
        return SIGAR_OK;
    }

    otime = prev->total;

    status = get_proc_time(pid, *(sigar_proc_time_t*)&proccpu);

    if (status != SIGAR_OK) {
        return status;
    }

    if (proccpu.total < otime) {
        /* XXX this should not happen */
        otime = 0;
    }

    if (otime == 0) {
        /* first time called */
        proccpu.percent = 0.0;
    } else {
        total_diff = proccpu.total - otime;
        proccpu.percent = total_diff / (double)time_diff;
    }

    memcpy(prev, &proccpu, sizeof(*prev));

    return SIGAR_OK;
}

int sigar_proc_list_create(sigar_proc_list_t* proclist) {
    proclist->number = 0;
    proclist->size = SIGAR_PROC_LIST_MAX;
    proclist->data = static_cast<sigar_pid_t*>(
            malloc(sizeof(*(proclist->data)) * proclist->size));
    return SIGAR_OK;
}

int sigar_proc_list_grow(sigar_proc_list_t* proclist) {
    proclist->data = static_cast<sigar_pid_t*>(
            realloc(proclist->data,
                    sizeof(*(proclist->data)) *
                            (proclist->size + SIGAR_PROC_LIST_MAX)));
    proclist->size += SIGAR_PROC_LIST_MAX;

    return SIGAR_OK;
}

SIGAR_DECLARE(int)
sigar_proc_list_destroy(sigar_t* sigar, sigar_proc_list_t* proclist) {
    if (proclist->size) {
        free(proclist->data);
        proclist->number = proclist->size = 0;
    }

    return SIGAR_OK;
}

SIGAR_DECLARE(int)
sigar_proc_list_get(sigar_t* sigar, sigar_proc_list_t* proclist) {
    if (proclist == NULL) {
        /* internal re-use */
        if (sigar->pids == NULL) {
            sigar->pids = static_cast<sigar_proc_list_t*>(
                    malloc(sizeof(*sigar->pids)));
            sigar_proc_list_create(sigar->pids);
        } else {
            sigar->pids->number = 0;
        }
        proclist = sigar->pids;
    } else {
        sigar_proc_list_create(proclist);
    }

    return sigar_os_proc_list_get(sigar, proclist);
}

SIGAR_DECLARE(int)
sigar_proc_list_get_children(sigar_t* sigar,
                             sigar_pid_t ppid,
                             sigar_proc_list_t* proclist) {
    if (proclist == NULL) {
        /* internal re-use */
        if (sigar->pids == NULL) {
            sigar->pids = static_cast<sigar_proc_list_t*>(
                    malloc(sizeof(*sigar->pids)));
            sigar_proc_list_create(sigar->pids);
        } else {
            sigar->pids->number = 0;
        }
        proclist = sigar->pids;
    } else {
        sigar_proc_list_create(proclist);
    }

    return sigar_os_proc_list_get_children(sigar, ppid, proclist);
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
