/*
 *    Copyright 2021-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include "sigar_port.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

static int is_interesting_process(const char* name) {
    return (strcmp(name, "moxi") != 0 && strcmp(name, "inet_gethost") != 0 &&
            strcmp(name, "memsup") != 0 && strcmp(name, "cpu_sup") != 0 &&
            strcmp(name, "sh") != 0 && strcmp(name, "epmd") != 0);
}

int find_interesting_procs(
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
