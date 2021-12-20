/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "sigar_port.h"

#include <errno.h>
#include <inttypes.h>
#include <sigar.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#define DEFAULT(value, def) ((value) == SIGAR_FIELD_NOTIMPL ? (def) : (value))

#define PROCS_REFRESH_INTERVAL 20

struct proc_stats {
    char name[PROC_NAME_LEN];
    uint32_t cpu_utilization;

    uint64_t pid;
    uint64_t ppid;

    uint64_t mem_size;
    uint64_t mem_resident;
    uint64_t mem_share;
    uint64_t minor_faults;
    uint64_t major_faults;
    uint64_t page_faults;
};

struct system_stats {
    uint32_t version;
    uint32_t struct_size;

    uint64_t cpu_total_ms;
    uint64_t cpu_idle_ms;
    uint64_t cpu_user_ms;
    uint64_t cpu_sys_ms;
    uint64_t cpu_irq_ms;
    uint64_t cpu_stolen_ms;

    uint64_t swap_total;
    uint64_t swap_used;

    uint64_t mem_total;
    uint64_t mem_used;
    uint64_t mem_actual_used;
    uint64_t mem_actual_free;

    uint64_t allocstall;

    struct proc_stats interesting_procs[NUM_INTERESTING_PROCS];
};

static int populate_interesting_procs(sigar_t* sigar,
                                      struct proc* procs,
                                      int procs_count,
                                      struct system_stats* reply) {
    int i;
    int stale = 0;

    sigar_proc_mem_t proc_mem;
    sigar_proc_cpu_t proc_cpu;

    struct proc_stats* child = reply->interesting_procs;

    for (i = 0; i < procs_count; ++i) {
        if (sigar_proc_mem_get(sigar, procs[i].pid, &proc_mem) != SIGAR_OK ||
            sigar_proc_cpu_get(sigar, procs[i].pid, &proc_cpu) != SIGAR_OK ||
            procs[i].start_time != proc_cpu.start_time) {
            stale = 1;
            continue;
        }

        child->pid = procs[i].pid;
        child->ppid = procs[i].ppid;
        strncpy(child->name, procs[i].name, PROC_NAME_LEN);
        child->cpu_utilization = DEFAULT((uint32_t)(100 * proc_cpu.percent), 0);
        child->mem_size = DEFAULT(proc_mem.size, 0);
        child->mem_resident = DEFAULT(proc_mem.resident, 0);
        child->mem_share = DEFAULT(proc_mem.share, 0);
        child->minor_faults = DEFAULT(proc_mem.minor_faults, 0);
        child->major_faults = DEFAULT(proc_mem.major_faults, 0);
        child->page_faults = DEFAULT(proc_mem.page_faults, 0);

        child++;
    }

    return stale;
}

static int parse_pid(char* pidstr, sigar_pid_t* result) {
    // The size and signed-ness of sigar_pid_t is different depending on the
    // system, but it is an integral type. So we use a maximum size integer
    // type to handle all systems uniformly.
    uintmax_t pid;
    char* pidend;

    errno = 0;
    pid = strtoumax(pidstr, &pidend, 10);
    if (errno != 0 || *pidend != '\0') {
        return 0;
    }

    // In general, this is incorrect, since we don't know if the value will
    // fit into the type. And there's no easy way to check that it will given
    // that we don't even know what sigar_pid_t is a typedef for. But since in
    // our case it's ns_server that passes the value, we should be fine.
    *result = (sigar_pid_t)pid;
    return 1;
}

int main(int argc, char* argv[]) {
    sigar_t* sigar;
    sigar_mem_t mem;
    sigar_swap_t swap;
    sigar_cpu_t cpu;
    struct system_stats reply;

    sigar_pid_t babysitter_pid;

    int procs_stale = 1;
    int procs_count;
    struct proc procs[NUM_INTERESTING_PROCS];

    int ticks_to_refresh = PROCS_REFRESH_INTERVAL;

    if (argc != 2 || !parse_pid(argv[1], &babysitter_pid)) {
        exit(1);
    }

    MUST_SUCCEED(sigar_open(&sigar));

#ifdef _WIN32
    _setmode(1, _O_BINARY);
    _setmode(0, _O_BINARY);
#endif

    while (!feof(stdin)) {
        int req;
        int rv = fread(&req, sizeof(req), 1, stdin);
        if (rv < 1) {
            continue;
        }
        if (req != 0) {
            break;
        }
        memset(&reply, 0, sizeof(reply));
        reply.version = 5;
        reply.struct_size = sizeof(reply);

        sigar_mem_get(sigar, &mem);
        sigar_swap_get(sigar, &swap);
        sigar_cpu_get(sigar, &cpu);

        reply.cpu_total_ms = cpu.total;
        reply.cpu_idle_ms = cpu.idle + cpu.wait;
        reply.cpu_user_ms = cpu.user + cpu.nice;
        reply.cpu_sys_ms = cpu.sys;
        reply.cpu_irq_ms = cpu.irq + cpu.soft_irq;
        reply.cpu_stolen_ms = cpu.stolen;

        reply.swap_total = swap.total;
        reply.swap_used = swap.used;

        reply.mem_total = mem.total;
        reply.mem_used = mem.used;
        reply.mem_actual_used = mem.actual_used;
        reply.mem_actual_free = mem.actual_free;

        if (swap.allocstall != -1) {
            reply.allocstall = swap.allocstall;
        } else if (swap.allocstall_dma != -1 && swap.allocstall_dma32 != -1 &&
                   swap.allocstall_normal != -1 &&
                   swap.allocstall_movable != -1) {
            reply.allocstall = swap.allocstall_dma + swap.allocstall_dma32 +
                               swap.allocstall_normal + swap.allocstall_movable;
        } else {
            reply.allocstall = -1;
        }

        if (procs_stale || ticks_to_refresh-- == 0) {
            ticks_to_refresh = PROCS_REFRESH_INTERVAL;
            procs_count = find_interesting_procs(sigar, babysitter_pid, procs);
        }

        procs_stale =
                populate_interesting_procs(sigar, procs, procs_count, &reply);

        fwrite(&reply, sizeof(reply), 1, stdout);
        fflush(stdout);
    }

    sigar_close(sigar);
    return 0;
}
