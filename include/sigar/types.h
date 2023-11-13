/*
 *     Copyright 2023-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#pragma once

#include <sys/types.h>

#ifdef __cplusplus
#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <string_view>
#else
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#endif

#ifdef WIN32
typedef uint64_t sigar_pid_t;
#else
typedef pid_t sigar_pid_t;
#endif

struct sigar_mem_t {
#ifdef __cplusplus
    sigar_mem_t() : total(0), used(0), free(0), actual_used(0), actual_free(0) {
    }
#endif
    uint64_t total; // Total amount of memory in bytes
    uint64_t used; // Total - free
    uint64_t free; // Total amount of memory available
    uint64_t actual_used; // Current usage
    uint64_t actual_free; // Current free
};

struct sigar_swap_t {
#ifdef __cplusplus
    sigar_swap_t()
        : total(std::numeric_limits<uint64_t>::max()),
          used(std::numeric_limits<uint64_t>::max()),
          free(std::numeric_limits<uint64_t>::max()),
          allocstall(std::numeric_limits<uint64_t>::max()) {
    }
#endif

    uint64_t total;
    uint64_t used;
    uint64_t free;
    uint64_t allocstall;
};

struct sigar_cpu_t {
#ifdef __cplusplus
    sigar_cpu_t()
        : user(std::numeric_limits<uint64_t>::max()),
          sys(std::numeric_limits<uint64_t>::max()),
          nice(std::numeric_limits<uint64_t>::max()),
          idle(std::numeric_limits<uint64_t>::max()),
          wait(std::numeric_limits<uint64_t>::max()),
          irq(std::numeric_limits<uint64_t>::max()),
          soft_irq(std::numeric_limits<uint64_t>::max()),
          stolen(std::numeric_limits<uint64_t>::max()),
          total(std::numeric_limits<uint64_t>::max()) {
    }
#endif
    uint64_t user, sys, nice, idle, wait, irq, soft_irq, stolen, total;
};

struct sigar_proc_mem_t {
#ifdef __cplusplus
    sigar_proc_mem_t()
        : size(std::numeric_limits<uint64_t>::max()),
          resident(std::numeric_limits<uint64_t>::max()),
          share(std::numeric_limits<uint64_t>::max()),
          minor_faults(std::numeric_limits<uint64_t>::max()),
          major_faults(std::numeric_limits<uint64_t>::max()),
          page_faults(std::numeric_limits<uint64_t>::max()) {
    }
#endif
    uint64_t size, resident, share, minor_faults, major_faults, page_faults;
};

struct sigar_proc_cpu_t {
#ifdef __cplusplus
    sigar_proc_cpu_t() : start_time(0), user(0), sys(0) {
    }
    sigar_proc_cpu_t(uint64_t start, uint64_t u, uint64_t s)
        : start_time(start), user(u), sys(s) {
    }
#endif
    /// The start time is picked from the operating system and its base
    /// varies from implementation to implementation. The intended use
    /// of the member is to allow the caller to detect if multiple samples
    /// represents the same process (or if has been restarted since the
    /// last time). Note that sigar cannot _guarantee_ that the operating
    /// system didn't recycle the pid and ended up with the same start_time
    /// (but on unix-like systems the odds are pretty low as they typically
    /// increase the pid until it wraps around starting on the first
    /// available number, whereas Windows typically use a more aggressive
    /// policy of reusing the process id).
    uint64_t start_time;
    /// The amount (in milliseconds) the process spent running in userspace
    /// since the process was started
    uint64_t user;
    /// The amount (in milliseconds) the process spent running in kernel space
    /// since the process was started
    uint64_t sys;
};

#define SIGAR_PROC_NAME_LEN 128

struct sigar_proc_state_t {
#ifdef __cplusplus
    sigar_proc_state_t() : threads(std::numeric_limits<uint64_t>::max()) {
    }
#endif
    char name[SIGAR_PROC_NAME_LEN];
    sigar_pid_t ppid;
    uint64_t threads;
};

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
    uint64_t memory_cache;
    uint64_t memory_active_file;
    uint64_t memory_inactive_file;
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
#else
typedef struct sigar_mem_t sigar_mem_t;
typedef struct sigar_swap_t sigar_swap_t;
typedef struct sigar_cpu_t sigar_cpu_t;
typedef struct sigar_proc_mem_t sigar_proc_mem_t;
typedef struct sigar_proc_cpu_t sigar_proc_cpu_t;
typedef struct sigar_proc_state_t sigar_proc_state_t;
typedef struct sigar_control_group_info sigar_control_group_info_t;
#endif

#ifdef __cplusplus
namespace sigar {

/**
 * The IterateChildProcessCallback is called with the following
 * parameters:
 *   1. The process pid
 *   2. The parent pid
 *   3. The process start time
 *   4. The process name
 */
using IterateChildProcessCallback = std::function<void(
        sigar_pid_t, sigar_pid_t, uint64_t, std::string_view)>;

using sigar_tid_t = sigar_pid_t;

/// callback with thread id, name (if known; otherwise blank), user time
/// and system time in microseconds
///
/// Note that we don't support thread naming on all platforms and on those
/// platforms the name will be blank.
///
/// It is also worth noting that on some platforms that unless the thread name
/// is explicitly set it may be empty, may be the name of the process etc.
using IterateThreadCallback =
        std::function<void(sigar_tid_t, std::string_view, uint64_t, uint64_t)>;

// Stats that we track are analagous to those in linux /proc/diskstats, given
// that we primarily run on linux systems.
struct disk_usage_t {
    // Name of the disk
    std::string name;

    // reads completed successfully
    uint64_t reads = std::numeric_limits<uint64_t>::max();

    // bytes read
    uint64_t rbytes = std::numeric_limits<uint64_t>::max();

    // time spent reading (ms)
    std::chrono::milliseconds rtime = std::chrono::milliseconds(0);

    // writes completed
    uint64_t writes = std::numeric_limits<uint64_t>::max();

    // bytes written
    uint64_t wbytes = std::numeric_limits<uint64_t>::max();

    // time spent writing (ms)
    std::chrono::milliseconds wtime = std::chrono::milliseconds::max();

    // time spent doing I/Os (ms)
    std::chrono::milliseconds time = std::chrono::milliseconds::max();

    // I/Os currently in progress
    uint64_t queue = std::numeric_limits<uint64_t>::max();

    // Max queue depth of the device
    uint64_t queue_depth = std::numeric_limits<uint64_t>::max();
};

using IterateDiskCallback = std::function<void(const disk_usage_t&)>;

} // namespace sigar
#endif
