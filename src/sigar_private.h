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
#pragma once

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef WIN32
#include <windows.h>
#include <winreg.h>
#else
#include <unistd.h>
#include <stddef.h>
#include <strings.h>
#endif

#ifdef __APPLE__
#include <mach/mach_port.h>
#endif

#include "sigar_cache.h"

#ifdef __cplusplus
extern "C" {
#endif

struct sigar_t {
   unsigned long boot_time;
   int ticks;
   char errbuf[256];
   sigar_proc_list_t* pids;
   sigar_cache_t* proc_cpu;
#ifdef __linux__
   int pagesize;
#elif defined(WIN32)
   char *machine;
   int using_wide;
   long pagesize;
   HKEY handle;
   LPBYTE perfbuf;
   DWORD perfbuf_size;
#elif defined(__APPLE__)
   int pagesize;
   mach_port_t mach_port;
#else
#error "Unsupported platform"
#endif
};

#define SIGAR_ZERO(s) \
    memset(s, '\0', sizeof(*(s)))

#define SIGAR_STRNCPY(dest, src, len) \
    strncpy(dest, src, len); \
    dest[len-1] = '\0'

/* we use fixed size buffers pretty much everywhere */
/* this is strncpy + ensured \0 terminator */
#define SIGAR_SSTRCPY(dest, src) \
    SIGAR_STRNCPY(dest, src, sizeof(dest))

#ifndef strEQ
#define strEQ(s1, s2) (strcmp(s1, s2) == 0)
#endif

#ifndef strnEQ
#define strnEQ(s1, s2, n) (strncmp(s1, s2, n) == 0)
#endif

#ifdef WIN32
#define strcasecmp stricmp
#define strncasecmp strnicmp
#endif

#ifndef strcaseEQ
#define strcaseEQ(s1, s2) (strcasecmp(s1, s2) == 0)
#endif

#ifndef strncaseEQ
#define strncaseEQ(s1, s2, n) (strncasecmp(s1, s2, n) == 0)
#endif

#define SIGAR_MSEC 1000L
#define SIGAR_USEC 1000000L
#define SIGAR_NSEC 1000000000L

#define SIGAR_SEC2NANO(s) \
    ((uint64_t)(s) * (uint64_t)SIGAR_NSEC)

/* cpu ticks to milliseconds */
#define SIGAR_TICK2MSEC(s) \
   ((uint64_t)(s) * ((uint64_t)SIGAR_MSEC / (double)sigar->ticks))

#define SIGAR_TICK2NSEC(s) \
   ((uint64_t)(s) * ((uint64_t)SIGAR_NSEC / (double)sigar->ticks))

/* nanoseconds to milliseconds */
#define SIGAR_NSEC2MSEC(s) \
   ((uint64_t)(s) / ((uint64_t)1000000L))

#define SIGAR_CPU_INFO_MAX 4

#define SIGAR_CPU_LIST_MAX 4

#define SIGAR_PROC_LIST_MAX 256

#define SIGAR_PROC_ARGS_MAX 12

int sigar_os_open(sigar_t **sigar);

int sigar_os_close(sigar_t *sigar);

const char* sigar_os_error_string(sigar_t* sigar, int err);

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist);

int sigar_os_proc_list_get_children(sigar_t* sigar,
                                    sigar_pid_t ppid,
                                    sigar_proc_list_t* proclist);

int sigar_proc_list_create(sigar_proc_list_t *proclist);

int sigar_proc_list_grow(sigar_proc_list_t *proclist);

#define SIGAR_PROC_LIST_GROW(proclist) \
    if (proclist->number >= proclist->size) { \
        sigar_proc_list_grow(proclist); \
    }

typedef struct {
    unsigned long number;
    unsigned long size;
    char **data;
} sigar_proc_args_t;

int sigar_proc_args_create(sigar_proc_args_t *proclist);

int sigar_proc_args_grow(sigar_proc_args_t *procargs);

#define SIGAR_PROC_ARGS_GROW(procargs) \
    if (procargs->number >= procargs->size) { \
        sigar_proc_args_grow(procargs); \
    }

typedef struct {
    uint64_t
            start_time,
            user,
            sys,
            total;
} sigar_proc_time_t;

// Not used externally
int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_time_t *proctime);

#ifdef __cplusplus
}
#endif
