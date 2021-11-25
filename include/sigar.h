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

#include <limits.h>
#include <sigar_visibility.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_LP64)         || \
    defined(__LP64__)      || \
    defined(__64BIT__)     || \
    defined(__powerpc64__) || \
    defined(__osf__)
#define SIGAR_64BIT
#endif

   typedef int32_t sigar_int32_t;
   typedef int64_t sigar_int64_t;
   typedef uint32_t sigar_uint32_t;
   typedef uint64_t sigar_uint64_t;

#define SIGAR_FIELD_NOTIMPL -1

#define SIGAR_OK 0
#define SIGAR_START_ERROR 20000
#define SIGAR_ENOTIMPL       (SIGAR_START_ERROR + 1)
#define SIGAR_OS_START_ERROR (SIGAR_START_ERROR*2)

#ifdef WIN32
#   define SIGAR_ENOENT ERROR_FILE_NOT_FOUND
#   define SIGAR_EACCES ERROR_ACCESS_DENIED
#   define SIGAR_ENXIO  ERROR_BAD_DRIVER_LEVEL
#else
#   define SIGAR_ENOENT ENOENT
#   define SIGAR_EACCES EACCES
#   define SIGAR_ENXIO  ENXIO
#endif

#define SIGAR_DECLARE(type) SIGAR_PUBLIC_API type

#if defined(PATH_MAX)
#   define SIGAR_PATH_MAX PATH_MAX
#elif defined(MAXPATHLEN)
#   define SIGAR_PATH_MAX MAXPATHLEN
#else
#   define SIGAR_PATH_MAX 4096
#endif

#ifdef WIN32
typedef sigar_uint64_t sigar_pid_t;
typedef unsigned long sigar_uid_t;
typedef unsigned long sigar_gid_t;
#else
#include <sys/types.h>
typedef pid_t sigar_pid_t;
typedef uid_t sigar_uid_t;
typedef gid_t sigar_gid_t;
#endif

typedef struct sigar_t sigar_t;

SIGAR_DECLARE(int) sigar_open(sigar_t **sigar);

SIGAR_DECLARE(int) sigar_close(sigar_t *sigar);

SIGAR_DECLARE(sigar_pid_t) sigar_pid_get(sigar_t *sigar);

SIGAR_DECLARE(char *) sigar_strerror(sigar_t *sigar, int err);

/* system memory info */

typedef struct {
    sigar_uint64_t
        ram,
        total,
        used,
        free,
        actual_used,
        actual_free;
    double used_percent;
    double free_percent;
} sigar_mem_t;

SIGAR_DECLARE(int) sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem);

typedef struct {
    sigar_uint64_t
        total,
        used,
        free,
        page_in,
        page_out,
        allocstall,             /* up until 4.10 */
        allocstall_dma,         /* 4.10 onwards */
        allocstall_dma32,       /* 4.10 onwards */
        allocstall_normal,      /* 4.10 onwards */
        allocstall_movable;     /* 4.10 onwards */
} sigar_swap_t;

SIGAR_DECLARE(int) sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap);

typedef struct {
    sigar_uint64_t
        user,
        sys,
        nice,
        idle,
        wait,
        irq,
        soft_irq,
        stolen,
        total;
} sigar_cpu_t;

SIGAR_DECLARE(int) sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu);

typedef struct {
    double uptime;
} sigar_uptime_t;

typedef struct {
    unsigned long number;
    unsigned long size;
    sigar_pid_t *data;
} sigar_proc_list_t;

SIGAR_DECLARE(int) sigar_proc_list_get(sigar_t *sigar,
                                       sigar_proc_list_t *proclist);

SIGAR_DECLARE(int)
sigar_proc_list_get_children(sigar_t* sigar,
                             sigar_pid_t ppid,
                             sigar_proc_list_t* proclist);

SIGAR_DECLARE(int) sigar_proc_list_destroy(sigar_t *sigar,
                                           sigar_proc_list_t *proclist);


typedef struct {
    sigar_uint64_t
        size,
        resident,
        share,
        minor_faults,
        major_faults,
        page_faults;
} sigar_proc_mem_t;

SIGAR_DECLARE(int) sigar_proc_mem_get(sigar_t *sigar, sigar_pid_t pid,
                                      sigar_proc_mem_t *procmem);

typedef struct {
    sigar_uint64_t
        start_time,
        user,
        sys,
        total;
} sigar_proc_time_t;

// Not used externally
int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                                       sigar_proc_time_t *proctime);

typedef struct {
    /* must match sigar_proc_time_t fields */
    sigar_uint64_t
        start_time,
        user,
        sys,
        total;
    sigar_uint64_t last_time;
    double percent;
} sigar_proc_cpu_t;

SIGAR_DECLARE(int) sigar_proc_cpu_get(sigar_t *sigar, sigar_pid_t pid,
                                      sigar_proc_cpu_t *proccpu);

#define SIGAR_PROC_STATE_SLEEP  'S'
#define SIGAR_PROC_STATE_RUN    'R'
#define SIGAR_PROC_STATE_STOP   'T'
#define SIGAR_PROC_STATE_ZOMBIE 'Z'
#define SIGAR_PROC_STATE_IDLE   'D'

#define SIGAR_PROC_NAME_LEN 128

typedef struct {
    char name[SIGAR_PROC_NAME_LEN];
    char state;
    sigar_pid_t ppid;
    int tty;
    int priority;
    int nice;
    int processor;
    sigar_uint64_t threads;
} sigar_proc_state_t;

SIGAR_DECLARE(int) sigar_proc_state_get(sigar_t *sigar, sigar_pid_t pid,
                                        sigar_proc_state_t *procstate);

typedef struct {
    unsigned long number;
    unsigned long size;
    char **data;
} sigar_proc_args_t;

#ifdef __cplusplus
}
#endif

#endif
