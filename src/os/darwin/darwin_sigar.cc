/*
 * Copyright (c) 2004-2009 Hyperic, Inc.
 * Copyright (c) 2009 SpringSource, Inc.
 * Copyright (c) 2009-2010 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sigar/sigar.h>

#if defined(__APPLE__)

#include "sigar.h"
#include "sigar_private.h"

#include <libproc.h>
#include <mach/host_info.h>
#include <mach/kern_return.h>
#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_traps.h>
#include <mach/shared_region.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <cerrno>
#include <system_error>
#include <utility>
#include <vector>

#define SIGAR_TICK2MSEC(s) \
    ((uint64_t)(s) * ((uint64_t)SIGAR_MSEC / (double)sigar->ticks))

#define SIGAR_NSEC2MSEC(s) ((uint64_t)(s) / ((uint64_t)1000000L))
#define SIGAR_NSEC2USEC(s) ((uint64_t)(s) / ((uint64_t)1000L))

namespace sigar {
/**
 * Class to hold the system sized (constants which never change for the
 * lifetime of the process)
 */
class SystemSizes {
public:
    static SystemSizes& instance() {
        static SystemSizes instance;
        return instance;
    }

    /// The total memory for the machine
    const uint64_t totalMemory;
    /// The page size used on the machine
    const uint64_t pageSize;

protected:
    SystemSizes()
        : totalMemory(getSysctlValue("hw.memsize")),
          pageSize(getSysctlValue("vm.pagesize")) {
    }

    /**
     * Get the system configured value
     *
     * @param name the name to look for
     * @return the uint64_t value for the name
     */
    uint64_t getSysctlValue(const char* name) {
        size_t len = 0;
        // Determine the size of the variable (uint32 or uint64)
        if (sysctlbyname(name, nullptr, &len, nullptr, 0) != 0) {
            throw std::system_error(errno,
                                    std::system_category(),
                                    std::string("getSysctlValue(") + name +
                                            "): failed to determine size");
        }
        // Read the value
        if (len == sizeof(uint64_t)) {
            uint64_t ret = 0;
            if (sysctlbyname(name, &ret, &len, nullptr, 0) != 0) {
                throw std::system_error(errno,
                                        std::system_category(),
                                        std::string("getSysctlValue(") + name +
                                                "): failed to fetch value");
            }
            return ret;
        }

        if (len == sizeof(uint32_t)) {
            uint32_t ret;
            if (sysctlbyname("vm.pagesize", &ret, &len, nullptr, 0) != 0) {
                throw std::system_error(errno,
                                        std::system_category(),
                                        std::string("getSysctlValue(") + name +
                                                "): failed to fetch value");
            }
            return ret;
        }
        throw std::runtime_error(std::string("getSysctlValue(") + name +
                                 "): Unexpected variable size");
    }
};

class AppleSigar : public SigarIface {
public:
    AppleSigar()
        : SigarIface(),
          ticks(sysconf(_SC_CLK_TCK)),
          mach_port(mach_host_self()) {
    }
    sigar_mem_t get_memory() override;
    sigar_swap_t get_swap() override;
    sigar_cpu_t get_cpu() override;
    unsigned int get_cpu_count() override;
    sigar_proc_mem_t get_proc_memory(sigar_pid_t pid) override;
    sigar_proc_state_t get_proc_state(sigar_pid_t pid) override;
    void iterate_child_processes(
            sigar_pid_t ppid,
            sigar::IterateChildProcessCallback callback) override;
    void iterate_threads(sigar::IterateThreadCallback callback) override;
    void iterate_disks(sigar::IterateDiskCallback callback) override;
    sigar_control_group_info get_control_group_info() const override {
        sigar_control_group_info ret;
        ret.supported = false;
        return ret;
    }
    sigar_proc_cpu_t get_proc_cpu(sigar_pid_t pid) const override;

protected:
    vm_statistics64 get_vmstat();

    /**
     * Get the number of threads in the provided process
     *
     * @param pid the pid to look up
     * @return number of threads or std::numeric_limits<uint64_t>::max
     */
    static uint64_t get_proc_threads(sigar_pid_t pid);
    static kinfo_proc get_pinfo(sigar_pid_t pid);

    const int ticks;
    mach_port_t mach_port;
};

std::unique_ptr<SigarIface> NewAppleSigar() {
    return std::make_unique<AppleSigar>();
}

vm_statistics64 AppleSigar::get_vmstat() {
    vm_statistics64 vmstat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    const auto status = host_statistics64(
            mach_port, HOST_VM_INFO64, (host_info_t)&vmstat, &count);

    if (status == KERN_SUCCESS) {
        return vmstat;
    }

    throw std::system_error(
            errno, std::system_category(), "AppleSigar::get_vmstat()");
}

sigar_mem_t AppleSigar::get_memory() {
    sigar_mem_t mem;
    auto& sizes = SystemSizes::instance();
    const auto vmstat = get_vmstat();

    mem.total = sizes.totalMemory;
    mem.free = vmstat.free_count * sizes.pageSize;
    mem.used = mem.total - mem.free;

    uint64_t kern = vmstat.inactive_count * sizes.pageSize;
    mem.actual_free = mem.free + kern;
    mem.actual_used = mem.used - kern;
    return mem;
}

sigar_swap_t AppleSigar::get_swap() {
    sigar_swap_t swap;
    struct xsw_usage sw_usage;
    size_t size = sizeof(sw_usage);
    std::vector<int> mib{{CTL_VM, VM_SWAPUSAGE}};

    if (sysctl(mib.data(), mib.size(), &sw_usage, &size, nullptr, 0) != 0) {
        throw std::system_error(
                errno,
                std::system_category(),
                "AppleSigar::get_swap(): sysctl(CTL_VM,CTL_SWAPUSAGE) failed");
    }

    if (size != sizeof(sw_usage)) {
        throw std::runtime_error(
                "AppleSigar::get_swap(): sysctl(CTL_VM,CTL_SWAPUSAGE) returned "
                "unexpected struct size");
    }

    swap.total = sw_usage.xsu_total;
    swap.used = sw_usage.xsu_used;
    swap.free = sw_usage.xsu_avail;
    return swap;
}

sigar_cpu_t AppleSigar::get_cpu() {
    sigar_cpu_t cpu;
    kern_return_t status;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    host_cpu_load_info_data_t cpuload;

    status = host_statistics(
            mach_port, HOST_CPU_LOAD_INFO, (host_info_t)&cpuload, &count);

    if (status != KERN_SUCCESS) {
        throw std::system_error(std::error_code(errno, std::system_category()),
                                "AppleSigar::get_cpu(): host_statistics");
    }

    auto* sigar = this;
    cpu.user = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_USER]);
    cpu.sys = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_SYSTEM]);
    cpu.idle = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_IDLE]);
    cpu.nice = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_NICE]);
    cpu.total = cpu.user + cpu.nice + cpu.sys + cpu.idle;
    return cpu;
}

unsigned int AppleSigar::get_cpu_count() {
    unsigned int count;
    size_t len = sizeof(count);
    if (sysctlbyname("hw.logicalcpu", &count, &len, nullptr, 0) != 0) {
        throw std::system_error(
                errno,
                std::system_category(),
                "AppleSigar::get_cpu_count(): sysctl(hw.logicalcpu)");
    }
    return count;
}

static const struct kinfo_proc* lookup_proc(const std::vector<kinfo_proc>& proc,
                                            pid_t pid) {
    for (const auto& p : proc) {
        if (p.kp_proc.p_pid == pid) {
            return &p;
        }
    }
    return nullptr;
}

/**
 * Given the list of processes, try to check if pid descents from ppid
 *
 * @param proc all of the processes in the system
 * @param pid the pid to check
 * @param ppid the pid we want to check if we descents from
 * @return true if pid have ppid in its process tree
 */
static bool sigar_os_check_parents(const std::vector<kinfo_proc>& proc,
                                   pid_t pid,
                                   pid_t ppid) {
    do {
        const struct kinfo_proc* p = lookup_proc(proc, pid);
        if (!p) {
            return false;
        }

        if (p->kp_eproc.e_ppid == ppid) {
            return true;
        }
        pid = p->kp_eproc.e_ppid;
    } while (pid != 0);
    return false;
}

#define tv2msec(tv) \
    (((uint64_t)tv.tv_sec * SIGAR_MSEC) + (((uint64_t)tv.tv_usec) / 1000))

void AppleSigar::iterate_child_processes(
        sigar_pid_t ppid, sigar::IterateChildProcessCallback callback) {
    std::vector<int> mib{{CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0}};
    size_t len = 0;

    if (sysctl(mib.data(), mib.size(), nullptr, &len, nullptr, 0) < 0) {
        throw std::system_error(
                errno,
                std::system_category(),
                "iterate_child_processes(): sysctl to determine size failed");
    }

    std::vector<kinfo_proc> proc(len / sizeof(kinfo_proc));

    if (sysctl(mib.data(), mib.size(), proc.data(), &len, nullptr, 0) < 0) {
        throw std::system_error(errno,
                                std::system_category(),
                                "iterate_child_processes(): sysctl failed");
    }

    for (const auto& p : proc) {
        if (sigar_os_check_parents(proc, p.kp_proc.p_pid, ppid)) {
            callback(p.kp_proc.p_pid,
                     p.kp_eproc.e_ppid,
                     tv2msec(p.kp_proc.p_starttime),
                     p.kp_proc.p_comm);
        }
    }
}

kinfo_proc AppleSigar::get_pinfo(sigar_pid_t pid) {
    std::vector<int> mib = {{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}};
    kinfo_proc pinfo = {};
    size_t len = sizeof(pinfo);

    if (sysctl(mib.data(), mib.size(), &pinfo, &len, nullptr, 0) < 0) {
        throw std::system_error(std::error_code(errno, std::system_category()),
                                "AppleSigar::get_pinfo(): sysctl");
    }

    return pinfo;
}

sigar_proc_mem_t AppleSigar::get_proc_memory(sigar_pid_t pid) {
    sigar_proc_mem_t procmem;
    proc_taskinfo pti;

    int sz = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, sizeof(pti));
    if (sz != int(sizeof(pti))) {
        throw std::system_error(
                errno,
                std::system_category(),
                "get_proc_memory(): proc_pidinfo(PROC_PIDTASKINFO)");
    }

    procmem.size = pti.pti_virtual_size;
    procmem.resident = pti.pti_resident_size;
    procmem.page_faults = pti.pti_faults;
    return procmem;
}

#define tval2msec(tval) \
    ((tval.seconds * SIGAR_MSEC) + (tval.microseconds / 1000))

struct sigar_proc_time_t {
    uint64_t start_time, user, sys, total;
};

static int get_proc_times(sigar_pid_t pid, sigar_proc_time_t* time) {
    unsigned int count;
    time_value_t utime = {0, 0}, stime = {0, 0};
    task_basic_info_data_t ti;
    task_thread_times_info_data_t tti;
    task_port_t task, self;
    kern_return_t status;

    struct proc_taskinfo pti;
    int sz = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, sizeof(pti));

    if (sz == sizeof(pti)) {
        time->user = SIGAR_NSEC2MSEC(pti.pti_total_user);
        time->sys = SIGAR_NSEC2MSEC(pti.pti_total_system);
        time->total = time->user + time->sys;
        return SIGAR_OK;
    }

    self = mach_task_self();
    status = task_for_pid(self, pid, &task);
    if (status != KERN_SUCCESS) {
        return errno;
    }

    count = TASK_BASIC_INFO_COUNT;
    status = task_info(task, TASK_BASIC_INFO, (task_info_t)&ti, &count);
    if (status != KERN_SUCCESS) {
        if (task != self) {
            mach_port_deallocate(self, task);
        }
        return errno;
    }

    count = TASK_THREAD_TIMES_INFO_COUNT;
    status = task_info(task, TASK_THREAD_TIMES_INFO, (task_info_t)&tti, &count);
    if (status != KERN_SUCCESS) {
        if (task != self) {
            mach_port_deallocate(self, task);
        }
        return errno;
    }

    time_value_add(&utime, &ti.user_time);
    time_value_add(&stime, &ti.system_time);
    time_value_add(&utime, &tti.user_time);
    time_value_add(&stime, &tti.system_time);

    time->user = tval2msec(utime);
    time->sys = tval2msec(stime);
    time->total = time->user + time->sys;

    return SIGAR_OK;
}

sigar_proc_cpu_t AppleSigar::get_proc_cpu(sigar_pid_t pid) const {
    sigar_proc_time_t proctime;
    const auto pinfo = get_pinfo(pid);

    int st = get_proc_times(pid, &proctime);
    if (st != SIGAR_OK) {
        throw std::system_error(std::error_code(st, std::system_category()),
                                "AppleSigar::get_proc_time: get_proc_times()");
    }

    proctime.start_time = tv2msec(pinfo.kp_proc.p_starttime);
    return {proctime.start_time, proctime.user, proctime.sys};
}

uint64_t AppleSigar::get_proc_threads(sigar_pid_t pid) {
    // We don't have access privileges to look at another process, so there
    // is no point of even trying
    if (pid != getpid()) {
        return std::numeric_limits<uint64_t>::max();
    }

    mach_port_t task, self = mach_task_self();
    auto status = task_for_pid(self, pid, &task);
    if (status != KERN_SUCCESS) {
        throw std::system_error(std::error_code(errno, std::system_category()),
                                "AppleSigar::get_proc_threads: task_for_pid()");
    }

    thread_array_t threads;
    mach_msg_type_number_t count;
    status = task_threads(task, &threads, &count);
    if (status != KERN_SUCCESS) {
        throw std::system_error(std::error_code(errno, std::system_category()),
                                "AppleSigar::get_proc_threads: task_threads()");
    }

    vm_deallocate(self, (vm_address_t)threads, sizeof(thread_t) * count);

    return count;
}

sigar_proc_state_t AppleSigar::get_proc_state(sigar_pid_t pid) {
    sigar_proc_state_t procstate;
    const auto pinfo = get_pinfo(pid);
    SIGAR_SSTRCPY(procstate.name, pinfo.kp_proc.p_comm);
    procstate.ppid = pinfo.kp_eproc.e_ppid;
    procstate.threads = get_proc_threads(pid);
    return procstate;
}

void AppleSigar::iterate_threads(sigar::IterateThreadCallback callback) {
    auto self = mach_task_self();

    mach_port_t task;
    auto status = task_for_pid(self, getpid(), &task);
    if (status != KERN_SUCCESS) {
        throw std::system_error(
                std::error_code(errno, std::system_category()),
                "AppleSigar::iterate_process_threads: task_for_pid()");
    }

    thread_array_t threads;
    mach_msg_type_number_t count;

    status = task_threads(task, &threads, &count);
    if (status != KERN_SUCCESS) {
        throw std::system_error(
                std::error_code(errno, std::system_category()),
                "AppleSigar::iterate_process_threads: task_threads()");
    }

    for (mach_msg_type_number_t ii = 0; ii < count; ii++) {
        mach_msg_type_number_t info_count = THREAD_EXTENDED_INFO_COUNT;
        thread_extended_info info;

        status = thread_info(threads[ii],
                             THREAD_EXTENDED_INFO,
                             (thread_info_t)&info,
                             &info_count);
        if (status == KERN_SUCCESS) {
            std::string_view nm{info.pth_name, sizeof(info.pth_name)};
            const auto idx = nm.find('\0');
            if (idx != std::string_view::npos) {
                nm = {nm.data(), idx};
            }
            callback(threads[ii],
                     nm,
                     SIGAR_NSEC2USEC(info.pth_user_time),
                     SIGAR_NSEC2USEC(info.pth_system_time));
        }
    }

    vm_deallocate(self, (vm_address_t)threads, sizeof(thread_t) * count);
}

void AppleSigar::iterate_disks(sigar::IterateDiskCallback callback) {
    // Upstream sigar has Darwin and FreeBSD implementations but no
    // implementation that works on MacOS proper. Older versions of sigar
    // implemented something like this using statvfs for things like disk
    // space but we don't really care about the stats available there. It's
    // possible to get some stats via IOKit, the iostat source code has an
    // example, but it requires a large amount of code that doesn't "just work"
    // and further modification to get out some of the stats that we do care
    // about. Extended iostat implementations using IOKit are available on code
    // hosting websites, but that code also requires further modification to
    // make it work. Given that MacOS is a development platform and not a
    // supported production platform, it doesn't feel particularly worthwhile
    // to spend any significant amount of time on this.
}
} // namespace sigar
#else
namespace sigar {
std::unique_ptr<SigarIface> NewAppleSigar() {
    return {};
}
} // namespace sigar
#endif
