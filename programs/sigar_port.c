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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sigar.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#define DEFAULT(value, def) ((value) == SIGAR_FIELD_NOTIMPL ? (def) : (value))

#define NUM_INTERESTING_PROCS 10
#define PROC_NAME_LEN 12

struct proc {
    sigar_pid_t pid;
    sigar_uint64_t start_time;
    char name[PROC_NAME_LEN];
};

struct proc_stats {
    char name[PROC_NAME_LEN];
    uint32_t cpu_utilization;

    uint64_t pid;

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

    uint64_t swap_total;
    uint64_t swap_used;
    uint64_t swap_page_in;
    uint64_t swap_page_out;

    uint64_t mem_total;
    uint64_t mem_used;
    uint64_t mem_actual_used;
    uint64_t mem_actual_free;

    struct proc_stats interesting_procs[NUM_INTERESTING_PROCS];
};

static int find_interesting_procs(sigar_t *sigar, sigar_pid_t parent,
                                  struct proc procs[NUM_INTERESTING_PROCS])
{
    unsigned long i;
    int found = 0;

    sigar_proc_list_t proc_list;
    sigar_proc_state_t proc_state;
    sigar_proc_cpu_t proc_cpu;
    sigar_pid_t pid;

    sigar_proc_list_get(sigar, &proc_list);

    for (i = 0; i < proc_list.number; ++i) {
        pid = proc_list.data[i];

        if (sigar_proc_state_get(sigar, pid, &proc_state) != SIGAR_OK) {
            continue;
        }

        if (proc_state.ppid == parent &&
            strcmp(proc_state.name, "moxi") != 0) {

            procs[found].pid = pid;
            strncpy(procs[found].name, proc_state.name, PROC_NAME_LEN);

            if (sigar_proc_cpu_get(sigar, pid, &proc_cpu) != SIGAR_OK) {
                continue;
            }

            procs[found].start_time = proc_cpu.start_time;
            ++found;

            if (found == NUM_INTERESTING_PROCS) {
                break;
            }
        }
    }

    sigar_proc_list_destroy(sigar, &proc_list);

    return found;
}

static int populate_interesting_procs(sigar_t *sigar,
                                      struct proc *procs, int procs_count,
                                      struct system_stats *reply)
{
    int i;
    int stale = 0;

    sigar_proc_mem_t proc_mem;
    sigar_proc_cpu_t proc_cpu;

    struct proc_stats *child;

    for (i = 0; i < procs_count; ++i) {
        if (sigar_proc_mem_get(sigar, procs[i].pid, &proc_mem) != SIGAR_OK ||
            sigar_proc_cpu_get(sigar, procs[i].pid, &proc_cpu) != SIGAR_OK ||
            procs[i].start_time != proc_cpu.start_time)
        {
            stale = 1;
            continue;
        }

        child = &reply->interesting_procs[i];

        child->pid = procs[i].pid;
        strncpy(child->name, procs[i].name, PROC_NAME_LEN);
        child->cpu_utilization = DEFAULT((uint32_t) (100 * proc_cpu.percent), 0);
        child->mem_size = DEFAULT(proc_mem.size, 0);
        child->mem_resident = DEFAULT(proc_mem.resident, 0);
        child->mem_share = DEFAULT(proc_mem.share, 0);
        child->minor_faults = DEFAULT(proc_mem.minor_faults, 0);
        child->major_faults = DEFAULT(proc_mem.major_faults, 0);
        child->page_faults = DEFAULT(proc_mem.page_faults, 0);
    }

    return stale;
}

int main(void)
{
    sigar_t *sigar;
    sigar_mem_t mem;
    sigar_swap_t swap;
    sigar_cpu_t cpu;
    struct system_stats reply;

    sigar_pid_t pid;
    sigar_proc_state_t state;

    sigar_pid_t child_vm_pid;
    sigar_pid_t babysitter_pid;

    int procs_stale = 1;
    int procs_count;
    struct proc procs[NUM_INTERESTING_PROCS];

    sigar_open(&sigar);

    pid = sigar_pid_get(sigar);
    sigar_proc_state_get(sigar, pid, &state);
    child_vm_pid = state.ppid;

    sigar_proc_state_get(sigar, child_vm_pid, &state);
    babysitter_pid = state.ppid;

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
        reply.version = 2;
        reply.struct_size = sizeof(reply);

        sigar_mem_get(sigar, &mem);
        sigar_swap_get(sigar, &swap);
        sigar_cpu_get(sigar, &cpu);

        reply.cpu_total_ms = cpu.total;
        reply.cpu_idle_ms = cpu.idle + cpu.wait;

        reply.swap_total = swap.total;
        reply.swap_used = swap.used;
        reply.swap_page_in = swap.page_in;
        reply.swap_page_out = swap.page_out;

        reply.mem_total = mem.total;
        reply.mem_used = mem.used;
        reply.mem_actual_used = mem.actual_used;
        reply.mem_actual_free = mem.actual_free;

        if (procs_stale) {
            procs_count = find_interesting_procs(sigar, babysitter_pid, procs);
        }

        procs_stale = populate_interesting_procs(sigar, procs, procs_count, &reply);

        if (procs_count != NUM_INTERESTING_PROCS) {
            procs_stale = 1;
        }

        fwrite(&reply, sizeof(reply), 1, stdout);
        fflush(stdout);
    }

    return 0;
}
