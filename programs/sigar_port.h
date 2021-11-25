/*
 *    Copyright 2021-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */
#pragma once

#include <sigar_control_group.h>

#include <sigar.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MUST_SUCCEED(body)      \
    do {                        \
        int _ret = (body);      \
        if (_ret != SIGAR_OK) { \
            exit(1);            \
        }                       \
    } while (0)

#define NUM_INTERESTING_PROCS 40
#define PROC_NAME_LEN 60

struct proc {
    sigar_pid_t pid;
    sigar_pid_t ppid;
    uint64_t start_time;
    char name[PROC_NAME_LEN];
};

/// Find all of the descendants of the babysitter process and populate the
/// interesting_proc array with the more information about each process
///
/// \param sigar the library handle
/// \param babysitter_pid the pid of the babysitter
/// \param interesting_procs the array to populate
/// \return The number of processes found
int find_interesting_procs(
        sigar_t* sigar,
        sigar_pid_t babysitter_pid,
        struct proc interesting_procs[NUM_INTERESTING_PROCS]);

int sigar_port_main(sigar_pid_t babysitter, FILE* in, FILE* out);

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

// Version 6 added the control group information
#define CURRENT_SYSTEM_STAT_VERSION 6

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
    sigar_control_group_info_t control_group_info;
};

#ifdef __cplusplus
}
#endif
