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

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
#include <chrono>
#include <functional>
#include <string_view>
extern "C" {
#endif

#define SIGAR_FIELD_NOTIMPL -1

#define SIGAR_OK 0
#define SIGAR_START_ERROR 20000
#define SIGAR_ENOTIMPL (SIGAR_START_ERROR + 1)
#define SIGAR_NO_SUCH_PROCESS (SIGAR_START_ERROR + 2)
#define SIGAR_NO_MEMORY_COUNTER (SIGAR_START_ERROR + 3)
#define SIGAR_NO_PROCESS_COUNTER (SIGAR_START_ERROR + 4)
#define SIGAR_NO_PROCESSOR_COUNTER (SIGAR_START_ERROR + 5)

#define SIGAR_DECLARE(type) SIGAR_PUBLIC_API type

#ifdef WIN32
typedef uint64_t sigar_pid_t;
#else
typedef pid_t sigar_pid_t;
#endif

typedef struct sigar_t sigar_t;

SIGAR_DECLARE(int) sigar_open(sigar_t** sigar);

SIGAR_DECLARE(int) sigar_close(sigar_t* sigar);

SIGAR_DECLARE(sigar_pid_t) sigar_pid_get(sigar_t* sigar);

SIGAR_DECLARE(const char*) sigar_strerror(sigar_t* sigar, int err);

/* system memory info */

typedef struct {
    uint64_t ram, total, used, free, actual_used, actual_free;
    double used_percent;
    double free_percent;
} sigar_mem_t;

SIGAR_DECLARE(int) sigar_mem_get(sigar_t* sigar, sigar_mem_t* mem);

typedef struct {
    uint64_t total, used, free, page_in, page_out,
            allocstall, /* up until 4.10 */
            allocstall_dma, /* 4.10 onwards */
            allocstall_dma32, /* 4.10 onwards */
            allocstall_normal, /* 4.10 onwards */
            allocstall_movable; /* 4.10 onwards */
} sigar_swap_t;

SIGAR_DECLARE(int) sigar_swap_get(sigar_t* sigar, sigar_swap_t* swap);

typedef struct {
    uint64_t user, sys, nice, idle, wait, irq, soft_irq, stolen, total;
} sigar_cpu_t;

SIGAR_DECLARE(int) sigar_cpu_get(sigar_t* sigar, sigar_cpu_t* cpu);

typedef struct {
    uint64_t size, resident, share, minor_faults, major_faults, page_faults;
} sigar_proc_mem_t;

SIGAR_DECLARE(int)
sigar_proc_mem_get(sigar_t* sigar, sigar_pid_t pid, sigar_proc_mem_t* procmem);

typedef struct {
    /* must match sigar_proc_time_t fields */
    uint64_t start_time, user, sys, total;
    uint64_t last_time;
    double percent;
} sigar_proc_cpu_t;

SIGAR_DECLARE(int)
sigar_proc_cpu_get(sigar_t* sigar, sigar_pid_t pid, sigar_proc_cpu_t* proccpu);

#define SIGAR_PROC_NAME_LEN 128

typedef struct {
    char name[SIGAR_PROC_NAME_LEN];
    char state;
    sigar_pid_t ppid;
    int tty;
    int priority;
    int nice;
    int processor;
    uint64_t threads;
} sigar_proc_state_t;

SIGAR_DECLARE(int)
sigar_proc_state_get(sigar_t* sigar,
                     sigar_pid_t pid,
                     sigar_proc_state_t* procstate);

#ifdef __linux__
// To allow mocking around with the linux tests just add a prefix
SIGAR_PUBLIC_API void sigar_set_procfs_root(const char* root);
#endif

#ifdef __cplusplus
namespace sigar {

/**
 * The IterateChildProcessCallback is called with the following
 * parameters:
 *   1. The process pid
 *   2. The parent pid
 *   3. The process start time
 *   4. The process name
 */
using IterateChildProcessCallback = std::function<void(
        sigar_pid_t, sigar_pid_t, uint64_t, std::string_view)>;

/**
 * Iterate over the child processes
 *
 * @param sigar The sigar instance to use
 * @param pid The process to iterate over the child for
 * @param callback The callback to call for each child
 */
SIGAR_PUBLIC_API
void iterate_child_processes(sigar_t* sigar,
                             sigar_pid_t pid,
                             IterateChildProcessCallback callback);

using sigar_tid_t = sigar_pid_t;

/// callback with thread id, name (if known; otherwise blank), user time
/// and system time in microseconds
///
/// Note that we don't support thread naming on all platforms and on those
/// platforms the name will be blank.
///
/// It is also worth noting that on some platforms that unless the thread name
/// is explicitly set it may be empty, may be the name of the process etc.
using IterateThreadCallback =
        std::function<void(sigar_tid_t, std::string_view, uint64_t, uint64_t)>;

SIGAR_PUBLIC_API
void iterate_threads(IterateThreadCallback callback);

} // namespace sigar
}
#endif

#endif
