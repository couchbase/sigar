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

#include <sigar/types.h>
#include <cstdio>
#include <optional>

namespace sigar_port {
enum {
    SIGAR_NORMAL_EXIT,
    SIGAR_INVALID_USAGE,
    SIGAR_INIT_FAIL,
    SIGAR_NO_BABYSITTER,
    SIGAR_EXCEPTION,
    SIGAR_OTHER_EXCEPTION
};

/// Set to true if you want the system to convert values to a more
/// human readable form
extern bool human_readable_output;
/// Set the indentation you want for the JSON payload returned
extern int indentation;
/// Where sigar_port should try to read the next line of input
extern FILE* input;
/// Where sigar_port should try to write its output
extern FILE* output;
} // namespace sigar_port

int sigar_port_main(std::optional<sigar_pid_t> babysitter_pid);
int sigar_port_snapshot(std::optional<sigar_pid_t> babysitter_pid);
