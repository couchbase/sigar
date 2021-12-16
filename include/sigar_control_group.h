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

#include <sigar_visibility.h>

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

struct sigar_control_group_info {
    /// Does the underlying operating system support control groups.
    /// The rest of the structure will only be initialized on supported
    /// platforms
    uint8_t supported;
    /// Set to 1 for cgroup V1, and 2 for cgroup V2
    uint8_t version;
    /// The number of CPUs available in the cgroup (in % where 100% represents
    /// 1 full core). This is either calculated as part of the CPU quota or
    /// CPU sets.
    uint16_t num_cpu_prc;

    /// For information about the following values, see
    /// https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
    ///
    /// Their value will be set to 0 if the controller isn't enabled
    uint64_t memory_max;
    uint64_t memory_current;
    uint64_t usage_usec;
    uint64_t user_usec;
    uint64_t system_usec;
    uint64_t nr_periods;
    uint64_t nr_throttled;
    uint64_t throttled_usec;
    uint64_t nr_bursts;
    uint64_t burst_usec;
};

#ifdef __cplusplus
using sigar_control_group_info_t = sigar_control_group_info;
static_assert(sizeof(sigar_control_group_info_t) == 88,
              "Remember to update the version number in port_sigar as the "
              "struct changed");
#else
typedef struct sigar_control_group_info sigar_control_group_info_t;
#endif

SIGAR_PUBLIC_API void sigar_get_control_group_info(sigar_control_group_info_t*);

#ifdef __cplusplus
}
#endif
