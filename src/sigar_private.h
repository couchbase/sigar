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

#include <sigar.h>

#include <cctype>
#include <cstdlib>
#include <cstring>

#ifdef WIN32
#include <windows.h>
#include <winreg.h>
#else
#include <strings.h>
#include <unistd.h>
#include <cstddef>
#endif

#ifdef __APPLE__
#include <mach/mach_port.h>
#endif
#include <unordered_map>

struct sigar_proc_time_t {
    uint64_t start_time, user, sys, total;
};

struct sigar_t {
protected:
    sigar_t();

    void mem_calc_ram(sigar_mem_t& mem) {
        int64_t total = mem.total / 1024, diff;
        uint64_t lram = (mem.total / (1024 * 1024));
        int ram = (int)lram; /* must cast after division */
        int remainder = ram % 8;

        if (remainder > 0) {
            ram += (8 - remainder);
        }

        mem.ram = ram;

        diff = total - (mem.actual_free / 1024);
        mem.used_percent = (double)(diff * 100) / total;

        diff = total - (mem.actual_used / 1024);
        mem.free_percent = (double)(diff * 100) / total;
    }

    int get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime);

public:
    static sigar_t* New();

    ~sigar_t() {
        if (pids) {
            sigar_proc_list_destroy(this, pids);
            free(pids);
        }
#ifdef __WIN32__
        if (perfbuf) {
            free(perfbuf);
        }
        retval = RegCloseKey(sigar->handle);
#endif
    }

    int get_memory(sigar_mem_t& mem);
    int get_swap(sigar_swap_t& swap);
    int get_cpu(sigar_cpu_t& cpu);
    int get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem);
    int get_proc_cpu(sigar_pid_t pid, sigar_proc_cpu_t& proccpu);
    int get_proc_state(sigar_pid_t pid, sigar_proc_state_t& procstate);

    char errbuf[256] = {};
    sigar_proc_list_t* pids = nullptr;
    std::unordered_map<sigar_pid_t, sigar_proc_cpu_t> process_cache;
#ifdef __linux__
#elif defined(WIN32)
    long pagesize = 0;
    HKEY handle;
    LPBYTE perfbuf = nullptr;
    DWORD perfbuf_size = 0;
#elif defined(__APPLE__)
    const int ticks;
    int pagesize;
    mach_port_t mach_port;
#else
#error "Unsupported platform"
#endif
};

#define SSTRLEN(s) \
    (sizeof(s)-1)

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

#define SIGAR_PROC_LIST_MAX 256

int sigar_os_proc_list_get_children(sigar_t* sigar,
                                    sigar_pid_t ppid,
                                    sigar_proc_list_t* proclist);

int sigar_proc_list_create(sigar_proc_list_t *proclist);

int sigar_proc_list_grow(sigar_proc_list_t *proclist);

#define SIGAR_PROC_LIST_GROW(proclist) \
    if (proclist->number >= proclist->size) { \
        sigar_proc_list_grow(proclist); \
    }

