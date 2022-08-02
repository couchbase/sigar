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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT(value, def) ((value) == SIGAR_FIELD_NOTIMPL ? (def) : (value))

#define PROCS_REFRESH_INTERVAL 20

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

int sigar_port_main(sigar_pid_t babysitter_pid, FILE* in, FILE* out) {
    sigar_t* sigar;
    sigar_mem_t mem;
    sigar_swap_t swap;
    sigar_cpu_t cpu;
    struct system_stats reply;

    int procs_stale = 1;
    int procs_count;
    struct proc procs[NUM_INTERESTING_PROCS];

    int ticks_to_refresh = PROCS_REFRESH_INTERVAL;

    MUST_SUCCEED(sigar_open(&sigar));

    while (!feof(in)) {
        int req;
        int rv = fread(&req, sizeof(req), 1, in);
        if (rv < 1) {
            continue;
        }
        if (req != 0) {
            break;
        }
        memset(&reply, 0, sizeof(reply));
        reply.version = CURRENT_SYSTEM_STAT_VERSION;
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

        if (swap.allocstall != SIGAR_FIELD_NOTIMPL) {
            reply.allocstall = swap.allocstall;
        } else {
            bool found = false;
            reply.allocstall = 0;
            if (swap.allocstall_dma != SIGAR_FIELD_NOTIMPL) {
                found = true;
                reply.allocstall += swap.allocstall_dma;
            }
            if (swap.allocstall_dma32 != SIGAR_FIELD_NOTIMPL) {
                found = true;
                reply.allocstall += swap.allocstall_dma32;
            }
            if (swap.allocstall_normal != SIGAR_FIELD_NOTIMPL) {
                found = true;
                reply.allocstall += swap.allocstall_normal;
            }

            if (swap.allocstall_movable != SIGAR_FIELD_NOTIMPL) {
                found = true;
                reply.allocstall += swap.allocstall_movable;
            }
            if (!found) {
                reply.allocstall = SIGAR_FIELD_NOTIMPL;
            }
        }

        if (procs_stale || ticks_to_refresh-- == 0) {
            ticks_to_refresh = PROCS_REFRESH_INTERVAL;
            procs_count = find_interesting_procs(sigar, babysitter_pid, procs);
        }

        procs_stale =
                populate_interesting_procs(sigar, procs, procs_count, &reply);

        sigar_get_control_group_info(&reply.control_group_info);
        fwrite(&reply, sizeof(reply), 1, out);
        fflush(out);
    }

    sigar_close(sigar);
    return 0;
}
