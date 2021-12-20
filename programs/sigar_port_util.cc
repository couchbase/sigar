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
#include <stdexcept>
#include <string>

static bool is_interesting_process(std::string_view name) {
    return !(name == "moxi" || name == "inet_gethost" || name == "memsup" ||
             name == "cpu_sup" || name == "sh" || name == "epmd");
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

    try {
        sigar::iterate_child_pocesses(
                sigar,
                babysitter_pid,
                [&interesting_count, &interesting_procs](
                        sigar_pid_t pid,
                        sigar_pid_t ppid,
                        uint64_t start_time,
                        std::string_view name) {
                    if (is_interesting_process(name) &&
                        interesting_count < NUM_INTERESTING_PROCS) {
                        std::string procname(name);
                        interesting_procs[interesting_count].pid = pid;
                        interesting_procs[interesting_count].ppid = ppid;
                        interesting_procs[interesting_count].start_time =
                                start_time;
                        strncpy(interesting_procs[interesting_count].name,
                                procname.c_str(),
                                PROC_NAME_LEN);
                        interesting_count++;
                    }
                });
    } catch (const std::exception&) {
        // ignore
    }

    return interesting_count;
}
