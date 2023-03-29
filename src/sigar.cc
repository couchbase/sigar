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

#include <memory>
#include <system_error>
#ifdef WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#include "sigar_private.h"
#include <sigar.h>

SIGAR_DECLARE(int) sigar_open(sigar_t** sigar) {
    try {
        *sigar = std::make_unique<sigar_t>().release();
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

SIGAR_DECLARE(sigar_pid_t) sigar_pid_get(sigar_t*) {
    return getpid();
}

SIGAR_DECLARE(int) sigar_mem_get(sigar_t* sigar, sigar_mem_t* mem) {
    if (!sigar || !mem) {
        return EINVAL;
    }
    try {
        *mem = sigar->instance->get_memory();
        return SIGAR_OK;
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

    try {
        *swap = sigar->instance->get_swap();
        return SIGAR_OK;
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

    try {
        *cpu = sigar->instance->get_cpu();
        return SIGAR_OK;
    } catch (const std::bad_alloc&) {
        return ENOMEM;
    } catch (const std::system_error& ex) {
        return ex.code().value();
    } catch (...) {
        return EINVAL;
    }
}

SIGAR_DECLARE(int)
sigar_proc_mem_get(sigar_t* sigar, sigar_pid_t pid, sigar_proc_mem_t* procmem) {
    if (!sigar || !procmem) {
        return EINVAL;
    }

    try {
        *procmem = sigar->instance->get_proc_memory(pid);
        return SIGAR_OK;
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

    try {
        *proccpu = sigar->instance->get_proc_cpu(pid);
        return SIGAR_OK;
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

    try {
        *procstate = sigar->instance->get_proc_state(pid);
        return SIGAR_OK;
    } catch (const std::bad_alloc&) {
        return ENOMEM;
    } catch (const std::system_error& ex) {
        return ex.code().value();
    } catch (...) {
        return EINVAL;
    }
}

SIGAR_PUBLIC_API
void sigar::iterate_threads(IterateThreadCallback callback) {
    SigarIface::New()->iterate_threads(callback);
}
