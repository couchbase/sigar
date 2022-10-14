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

#define SIGAR_PROC_STATE_SLEEP 'S'
#define SIGAR_PROC_STATE_RUN 'R'
#define SIGAR_PROC_STATE_STOP 'T'
#define SIGAR_PROC_STATE_ZOMBIE 'Z'
#define SIGAR_PROC_STATE_IDLE 'D'

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

class AppleSigar : public sigar_t {
public:
    AppleSigar()
        : sigar_t(),
          ticks(sysconf(_SC_CLK_TCK)),
          mach_port(mach_host_self()) {
    }
    int get_memory(sigar_mem_t& mem) override;
    int get_swap(sigar_swap_t& swap) override;
    int get_cpu(sigar_cpu_t& cpu) override;
    int get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem) override;
    int get_proc_state(sigar_pid_t pid, sigar_proc_state_t& procstate) override;
    void iterate_child_processes(
            sigar_pid_t ppid,
            sigar::IterateChildProcessCallback callback) override;
    void iterate_threads(sigar::IterateThreadCallback callback) override;
    void iterate_disks(sigar::IterateDiskCallback callback) override;

protected:
    int get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime) override;

    vm_statistics64 get_vmstat();

    static int get_proc_threads(sigar_pid_t pid, sigar_proc_state_t& procstate);
    static std::pair<int, kinfo_proc> get_pinfo(sigar_pid_t pid);

    const int ticks;
    mach_port_t mach_port;
};

sigar_t::sigar_t() = default;

std::unique_ptr<sigar_t> sigar_t::New() {
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

int AppleSigar::get_memory(sigar_mem_t& mem) {
    auto& sizes = SystemSizes::instance();
    const auto vmstat = get_vmstat();

    mem.total = sizes.totalMemory;
    mem.free = vmstat.free_count * sizes.pageSize;
    mem.used = mem.total - mem.free;

    uint64_t kern = vmstat.inactive_count * sizes.pageSize;
    mem.actual_free = mem.free + kern;
    mem.actual_used = mem.used - kern;
    mem_calc_ram(mem);

    return SIGAR_OK;
}

int AppleSigar::get_swap(sigar_swap_t& swap) {
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

    const auto vmstat = get_vmstat();
    swap.page_in = vmstat.pageins;
    swap.page_out = vmstat.pageouts;

    return SIGAR_OK;
}

int AppleSigar::get_cpu(sigar_cpu_t& cpu) {
    kern_return_t status;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    host_cpu_load_info_data_t cpuload;

    status = host_statistics(
            mach_port, HOST_CPU_LOAD_INFO, (host_info_t)&cpuload, &count);

    if (status != KERN_SUCCESS) {
        return errno;
    }

    auto* sigar = this;
    cpu.user = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_USER]);
    cpu.sys = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_SYSTEM]);
    cpu.idle = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_IDLE]);
    cpu.nice = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_NICE]);
    cpu.total = cpu.user + cpu.nice + cpu.sys + cpu.idle;

    return SIGAR_OK;
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

std::pair<int, kinfo_proc> AppleSigar::get_pinfo(sigar_pid_t pid) {
    std::vector<int> mib = {{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}};
    kinfo_proc pinfo = {};
    size_t len = sizeof(pinfo);

    if (sysctl(mib.data(), mib.size(), &pinfo, &len, nullptr, 0) < 0) {
        return {errno, {}};
    }

    return {SIGAR_OK, pinfo};
}

int AppleSigar::get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem) {
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

    return SIGAR_OK;
}

#define tval2msec(tval) \
    ((tval.seconds * SIGAR_MSEC) + (tval.microseconds / 1000))

static int get_proc_times(sigar_t*, sigar_pid_t pid, sigar_proc_time_t* time) {
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

int AppleSigar::get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime) {
    const auto [status, pinfo] = get_pinfo(pid);
    if (status != SIGAR_OK) {
        return status;
    }

    int st = get_proc_times(this, pid, &proctime);
    if (st != SIGAR_OK) {
        return st;
    }

    proctime.start_time = tv2msec(pinfo.kp_proc.p_starttime);
    return SIGAR_OK;
}

/* thread state mapping derived from ps.tproj */
static const char thread_states[] = {
        /*0*/ '-',
        /*1*/ SIGAR_PROC_STATE_RUN,
        /*2*/ SIGAR_PROC_STATE_ZOMBIE,
        /*3*/ SIGAR_PROC_STATE_SLEEP,
        /*4*/ SIGAR_PROC_STATE_IDLE,
        /*5*/ SIGAR_PROC_STATE_STOP,
        /*6*/ SIGAR_PROC_STATE_STOP,
        /*7*/ '?'};

static int thread_state_get(thread_basic_info_data_t* info) {
    switch (info->run_state) {
    case TH_STATE_RUNNING:
        return 1;
    case TH_STATE_UNINTERRUPTIBLE:
        return 2;
    case TH_STATE_WAITING:
        return (info->sleep_time > 20) ? 4 : 3;
    case TH_STATE_STOPPED:
        return 5;
    case TH_STATE_HALTED:
        return 6;
    default:
        return 7;
    }
}

int AppleSigar::get_proc_threads(sigar_pid_t pid,
                                 sigar_proc_state_t& procstate) {
    mach_port_t task, self = mach_task_self();
    kern_return_t status;
    thread_array_t threads;
    mach_msg_type_number_t count, i;
    int state = TH_STATE_HALTED + 1;

    status = task_for_pid(self, pid, &task);
    if (status != KERN_SUCCESS) {
        return errno;
    }

    status = task_threads(task, &threads, &count);
    if (status != KERN_SUCCESS) {
        return errno;
    }

    procstate.threads = count;

    for (i = 0; i < count; i++) {
        mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;
        thread_basic_info_data_t info;

        status = thread_info(threads[i],
                             THREAD_BASIC_INFO,
                             (thread_info_t)&info,
                             &info_count);
        if (status == KERN_SUCCESS) {
            int tstate = thread_state_get(&info);
            if (tstate < state) {
                state = tstate;
            }
        }
    }

    vm_deallocate(self, (vm_address_t)threads, sizeof(thread_t) * count);

    procstate.state = thread_states[state];
    return SIGAR_OK;
}

int AppleSigar::get_proc_state(sigar_pid_t pid, sigar_proc_state_t& procstate) {
    const auto [status, pinfo] = get_pinfo(pid);
    if (status != SIGAR_OK) {
        return status;
    }
    int state = pinfo.kp_proc.p_stat;

    SIGAR_SSTRCPY(procstate.name, pinfo.kp_proc.p_comm);
    procstate.ppid = pinfo.kp_eproc.e_ppid;
    procstate.priority = pinfo.kp_proc.p_priority;
    procstate.nice = pinfo.kp_proc.p_nice;

    auto st = get_proc_threads(pid, procstate);
    if (st == SIGAR_OK) {
        return st;
    }

    switch (state) {
    case SIDL:
        procstate.state = 'D';
        break;
    case SRUN:
#ifdef SONPROC
    case SONPROC:
#endif
        procstate.state = 'R';
        break;
    case SSLEEP:
        procstate.state = 'S';
        break;
    case SSTOP:
        procstate.state = 'T';
        break;
    case SZOMB:
        procstate.state = 'Z';
        break;
    default:
        procstate.state = '?';
        break;
    }

    return SIGAR_OK;
}

void AppleSigar::iterate_threads(sigar::IterateThreadCallback callback) {
    auto self = mach_task_self();

    mach_port_t task;
    auto status = task_for_pid(self, getpid(), &task);
    if (status != KERN_SUCCESS) {
        throw std::runtime_error(
                "iterate_process_threads: task_for_pid() failed with "
                "error: " +
                std::to_string(status));
    }

    thread_array_t threads;
    mach_msg_type_number_t count;

    status = task_threads(task, &threads, &count);
    if (status != KERN_SUCCESS) {
        throw std::system_error(errno,
                                std::system_category(),
                                "iterate_process_threads: task_threads()");
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
#endif