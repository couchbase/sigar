/*
 *    Copyright 2021-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include <cgroup/cgroup.h>
#include <sigar_control_group.h>
#include <exception>
#include <iostream>

void sigar_get_control_group_info(sigar_control_group_info_t* info) {
    auto& instance = cb::cgroup::ControlGroup::instance();
    try {
        info->supported = 1;
        info->version = uint8_t(instance.get_version());
        info->num_cpu_prc = uint16_t(instance.get_available_cpu());
        info->memory_max = instance.get_max_memory();
        info->memory_current = instance.get_current_memory();
        info->memory_cache = instance.get_current_cache_memory();
        const auto stats = instance.get_cpu_stats();
        info->usage_usec = stats.usage.count();
        info->user_usec = stats.user.count();
        info->system_usec = stats.system.count();
        info->nr_periods = stats.nr_periods;
        info->nr_throttled = stats.nr_throttled;
        info->throttled_usec = stats.throttled.count();
        info->nr_bursts = stats.nr_bursts;
        info->burst_usec = stats.burst.count();
    } catch (const std::exception& exception) {
        std::cerr << "sigar_get_control_group_info(): exception: "
                  << exception.what() << std::endl;
        info->supported = 0;
    }
}