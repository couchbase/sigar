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
#include <array>
#include <cstdio>
#include <string>

constexpr std::size_t NUM_INTERESTING_PROCS = 40;
constexpr std::size_t PROC_NAME_LEN = 60;

int sigar_port_main(sigar_pid_t babysitter, FILE* in, FILE* out);

struct proc_stats {
    std::array<char, PROC_NAME_LEN> name;
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

// Version 7 extended the control group information
constexpr uint32_t CURRENT_SYSTEM_STAT_VERSION = 7;

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

    std::array<proc_stats, NUM_INTERESTING_PROCS> interesting_procs;
    sigar_control_group_info_t control_group_info;
};

static_assert(sizeof(system_stats) == 5328, "Unexpected struct size");
