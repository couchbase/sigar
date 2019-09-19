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
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sigar.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#define DEFAULT(value, def) ((value) == SIGAR_FIELD_NOTIMPL ? (def) : (value))
#define MUST_SUCCEED(body)                      \
    do {                                        \
        int _ret = (body);                      \
        if (_ret != SIGAR_OK) {                 \
            exit(1);                            \
        }                                       \
    } while (0)

#define NUM_INTERESTING_PROCS 40
#define PROCS_REFRESH_INTERVAL 20
#define PROC_NAME_LEN 60

struct proc {
    sigar_pid_t pid;
    sigar_pid_t ppid;
    sigar_uint64_t start_time;
    char name[PROC_NAME_LEN];
};

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

static int is_interesting_process(const char *name)
{
    return (strcmp(name, "moxi") != 0 &&
            strcmp(name, "inet_gethost") != 0 &&
            strcmp(name, "memsup") != 0 &&
            strcmp(name, "cpu_sup") != 0 &&
            strcmp(name, "sh") != 0 &&
            strcmp(name, "epmd") != 0);
}

/// Find all of the descendants of the babysitter process and populate the
/// interesting_proc array with the more information about each process
///
/// \param sigar the library handle
/// \param babysitter_pid the pid of the babysitter
/// \param interesting_procs the array to populate
/// \return The number of processes found
static int find_interesting_procs(
        sigar_t* sigar,
        sigar_pid_t babysitter_pid,
        struct proc interesting_procs[NUM_INTERESTING_PROCS]) {
    sigar_proc_state_t proc_state;
    sigar_proc_cpu_t proc_cpu;

    if (sigar_proc_state_get(sigar, babysitter_pid, &proc_state) != SIGAR_OK ||
        sigar_proc_cpu_get(sigar, babysitter_pid, &proc_cpu) != SIGAR_OK) {
        fprintf(stderr,
                "Failed to lookup the babysitter process with pid %u",
                babysitter_pid);
        exit(1);
    }

    int interesting_count = 0;
    interesting_procs[interesting_count].pid = babysitter_pid;
    interesting_procs[interesting_count].ppid = proc_state.ppid;
    interesting_procs[interesting_count].start_time = proc_cpu.start_time;
    strncpy(interesting_procs[interesting_count].name,
            proc_state.name,
            PROC_NAME_LEN);
    interesting_count++;

    sigar_proc_list_t proc_list;
    MUST_SUCCEED(
            sigar_proc_list_get_children(sigar, babysitter_pid, &proc_list));

    for (unsigned long i = 0; i < proc_list.number; ++i) {
        sigar_pid_t pid = proc_list.data[i];

        if (sigar_proc_state_get(sigar, pid, &proc_state) != SIGAR_OK) {
            continue;
        }

        if (sigar_proc_cpu_get(sigar, pid, &proc_cpu) != SIGAR_OK) {
            continue;
        }

        if (is_interesting_process(proc_state.name) &&
            interesting_count < NUM_INTERESTING_PROCS) {
            interesting_procs[interesting_count].pid = pid;
            interesting_procs[interesting_count].ppid = proc_state.ppid;
            interesting_procs[interesting_count].start_time =
                    proc_cpu.start_time;
            strncpy(interesting_procs[interesting_count].name,
                    proc_state.name,
                    PROC_NAME_LEN);
            interesting_count++;
        }
    }

    MUST_SUCCEED(sigar_proc_list_destroy(sigar, &proc_list));

    return interesting_count;
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
        child->ppid = procs[i].ppid;
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

static int parse_pid(char *pidstr, sigar_pid_t *result)
{
    // The size and signed-ness of sigar_pid_t is different depending on the
    // system, but it is an integral type. So we use a maximum size integer
    // type to handle all systems uniformly.
    uintmax_t pid;
    char *pidend;

    errno = 0;
    pid = strtoumax(pidstr, &pidend, 10);
    if (errno != 0 || *pidend != '\0') {
        return 0;
    }

    // In general, this is incorrect, since we don't know if the value will
    // fit into the type. And there's no easy way to check that it will given
    // that we don't even know what sigar_pid_t is a typedef for. But since in
    // our case it's ns_server that passes the value, we should be fine.
    *result = (sigar_pid_t) pid;
    return 1;
}

int main(int argc, char *argv[])
{
    sigar_t *sigar;
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
        reply.version = 3;
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

        if (procs_stale || ticks_to_refresh-- == 0) {
            ticks_to_refresh = PROCS_REFRESH_INTERVAL;
            procs_count = find_interesting_procs(sigar, babysitter_pid, procs);
        }

        procs_stale = populate_interesting_procs(sigar, procs, procs_count, &reply);

        fwrite(&reply, sizeof(reply), 1, stdout);
        fflush(stdout);
    }

    sigar_close(sigar);
    return 0;
}
