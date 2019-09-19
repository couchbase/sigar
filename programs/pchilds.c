/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2019 Couchbase, Inc.
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
#include <sigar.h>
#include <stdio.h>

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

/// Print all of the processes being a descendants of the provided pid.
/// This program is not being installed and its sole purpose is to be able
/// to test sigar_proc_list_get_children and that we can map those pids
/// to the process name (it is being used in sigar_port, but it is not that
/// easy to test on all platform (looking at windows..)
int main(int argc, char** argv) {
    sigar_t* sigar;
    sigar_pid_t parent_pid;
    sigar_proc_list_t proc_list;

    if (argc != 2) {
        fprintf(stderr, "Usage: pchilds <pid>\n");
        return 1;
    }

    if (!parse_pid(argv[1], &parent_pid)) {
        fprintf(stderr, "Failed to parse pid from \"%s\"\n", argv[1]);
        return 1;
    }

    if (sigar_open(&sigar) != SIGAR_OK) {
        fprintf(stderr, "Failed to initialize sigar\n");
        return 1;
    }

    if (sigar_proc_list_get_children(sigar, parent_pid, &proc_list) !=
        SIGAR_OK) {
        fprintf(stderr, "Failed to fetch childrens\n");
        return 1;
    }

    for (unsigned long i = 0; i < proc_list.number; ++i) {
        sigar_pid_t pid = proc_list.data[i];
        sigar_proc_state_t proc_state;

        if (sigar_proc_state_get(sigar, pid, &proc_state) != SIGAR_OK) {
            fprintf(stderr, "Failed to look up %u\n", pid);
            continue;
        }

        fprintf(stdout, "%u - %s\n", pid, proc_state.name);
    }

    sigar_proc_list_destroy(sigar, &proc_list);
    sigar_close(sigar);
    return 0;
}
