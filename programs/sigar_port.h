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

#include <sigar.h>

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

#ifdef __cplusplus
}
#endif
