/*
 *     Copyright 2023-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include <sigar/sigar.h>
#include <system_error>

namespace sigar {

extern std::unique_ptr<SigarIface> NewAppleSigar();
extern std::unique_ptr<SigarIface> NewLinuxSigar();
extern std::unique_ptr<SigarIface> NewWin32Sigar();

std::unique_ptr<SigarIface> SigarIface::New(Backend backend) {
    switch (backend) {
    case Backend::Native:
#ifdef __APPLE__
        return NewAppleSigar();
#elif defined(__linux__)
        return NewLinuxSigar();
#else
        return NewWin32Sigar();
#endif
    case Backend::Apple:
        return NewAppleSigar();

    case Backend::Linux:
        return NewLinuxSigar();

    case Backend::Windows:
        return NewWin32Sigar();
    }
    throw std::invalid_argument("SigarIface::New: Unknown backend");
}

SigarIface::SigarIface() = default;

static uint64_t time_now_millis() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
                   now.time_since_epoch())
            .count();
}

sigar_proc_cpu_t SigarIface::get_proc_cpu(sigar_pid_t pid) {
    sigar_proc_cpu_t proccpu;
    const auto time_now = time_now_millis();
    sigar_proc_cpu_t prev = {};
    auto iter = process_cache.find(pid);
    const bool found = iter != process_cache.end();
    if (found) {
        prev = iter->second;
    }

    try {
        std::tie(proccpu.start_time, proccpu.user, proccpu.sys, proccpu.total) =
                get_proc_time(pid);
    } catch (const std::system_error&) {
        if (found) {
            process_cache.erase(iter);
        }
        throw;
    }

    proccpu.last_time = time_now;
    if (!found || (prev.start_time != proccpu.start_time)) {
        // This is a new process or a different process we have in the cache
        process_cache[pid] = proccpu;
        return proccpu;
    }

    auto time_diff = time_now - prev.last_time;
    if (!time_diff) {
        // we don't want divide by zero
        time_diff = 1;
    }
    proccpu.percent = (proccpu.total - prev.total) / (double)time_diff;
    process_cache[pid] = proccpu;

    return proccpu;
}

} // namespace sigar