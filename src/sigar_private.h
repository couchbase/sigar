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

#ifndef WIN32
#include <strings.h>
#include <unistd.h>
#include <cstddef>
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

    virtual int get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime) = 0;

public:
    static sigar_t* New();

    virtual ~sigar_t() = default;

    virtual int get_memory(sigar_mem_t& mem) = 0;
    virtual int get_swap(sigar_swap_t& swap) = 0;
    virtual int get_cpu(sigar_cpu_t& cpu) = 0;
    virtual int get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem) = 0;
    virtual int get_proc_state(sigar_pid_t pid,
                               sigar_proc_state_t& procstate) = 0;
    virtual void iterate_child_pocesses(
            sigar_pid_t pid, sigar::IterateChildProcessCallback callback) = 0;

    int get_proc_cpu(sigar_pid_t pid, sigar_proc_cpu_t& proccpu);

    char errbuf[256] = {};
    std::unordered_map<sigar_pid_t, sigar_proc_cpu_t> process_cache;
};

#define SIGAR_STRNCPY(dest, src, len) \
    strncpy(dest, src, len);          \
    dest[len - 1] = '\0'

/* we use fixed size buffers pretty much everywhere */
/* this is strncpy + ensured \0 terminator */
#define SIGAR_SSTRCPY(dest, src) SIGAR_STRNCPY(dest, src, sizeof(dest))

#define SIGAR_MSEC 1000L
