/*
 * Copyright (c) 2004-2008 Hyperic, Inc.
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

#ifndef SIGAR_H
#define SIGAR_H

/* System Information Gatherer And Reporter */

#include "sigar_visibility.h"
#include <sigar/types.h>

#include <sys/types.h>

#ifdef __cplusplus
#include <chrono>
#include <cinttypes>
#include <climits>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

extern "C" {
#else
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#endif

#define SIGAR_FIELD_NOTIMPL -1

#define SIGAR_OK 0
#define SIGAR_START_ERROR 20000
#define SIGAR_ENOTIMPL (SIGAR_START_ERROR + 1)
#define SIGAR_NO_SUCH_PROCESS (SIGAR_START_ERROR + 2)
#define SIGAR_NO_MEMORY_COUNTER (SIGAR_START_ERROR + 3)
#define SIGAR_NO_DISK_COUNTER (SIGAR_START_ERROR + 6)

#define SIGAR_DECLARE(type) SIGAR_PUBLIC_API type

typedef struct sigar_t sigar_t;

SIGAR_DECLARE(int) sigar_open(sigar_t** sigar);

SIGAR_DECLARE(int) sigar_close(sigar_t* sigar);

SIGAR_DECLARE(sigar_pid_t) sigar_pid_get(sigar_t* sigar);

SIGAR_DECLARE(const char*) sigar_strerror(sigar_t* sigar, int err);

/* system memory info */

SIGAR_DECLARE(int) sigar_mem_get(sigar_t* sigar, sigar_mem_t* mem);

SIGAR_DECLARE(int) sigar_swap_get(sigar_t* sigar, sigar_swap_t* swap);

SIGAR_DECLARE(int) sigar_cpu_get(sigar_t* sigar, sigar_cpu_t* cpu);

SIGAR_DECLARE(int)
sigar_proc_mem_get(sigar_t* sigar, sigar_pid_t pid, sigar_proc_mem_t* procmem);

SIGAR_DECLARE(int)
sigar_proc_cpu_get(sigar_t* sigar, sigar_pid_t pid, sigar_proc_cpu_t* proccpu);

SIGAR_DECLARE(int)
sigar_proc_state_get(sigar_t* sigar,
                     sigar_pid_t pid,
                     sigar_proc_state_t* procstate);

#ifdef __cplusplus
}
#endif

#endif
