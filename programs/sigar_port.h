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
#include <cstdio>
#include <optional>

int sigar_port_main(std::optional<sigar_pid_t> babysitter_pid,
                    FILE* in,
                    FILE* out);

int sigar_port_snapshot(std::optional<sigar_pid_t> babysitter_pid);
