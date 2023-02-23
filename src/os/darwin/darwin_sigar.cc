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

#include "sigar.h"
#include "sigar_private.h"

#include <cerrno>
#include <libproc.h>
#include <mach-o/dyld.h>
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
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <system_error>
#include <utility>

#define SIGAR_SEC2NANO(s) ((uint64_t)(s) * (uint64_t)SIGAR_NSEC)

#define SIGAR_TICK2MSEC(s) \
    ((uint64_t)(s) * ((uint64_t)SIGAR_MSEC / (double)sigar->ticks))

#define SIGAR_NSEC2MSEC(s) ((uint64_t)(s) / ((uint64_t)1000000L))
#define SIGAR_NSEC2USEC(s) ((uint64_t)(s) / ((uint64_t)1000L))

#define NMIB(mib) (sizeof(mib) / sizeof(mib[0]))

#define SIGAR_PROC_STATE_SLEEP 'S'
#define SIGAR_PROC_STATE_RUN 'R'
#define SIGAR_PROC_STATE_STOP 'T'
#define SIGAR_PROC_STATE_ZOMBIE 'Z'
#define SIGAR_PROC_STATE_IDLE 'D'

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
    size_t len;
    uint64_t mem_total;
    len = sizeof(mem_total);
    if (sysctlbyname("hw.memsize", &mem_total, &len, nullptr, 0) < 0) {
        throw std::system_error(
                errno, std::system_category(), R"(sysctlbyname("hw.memsize"))");
    }

    const auto vmstat = get_vmstat();
    uint64_t pagesize;
    len = sizeof(pagesize);
    if (sysctlbyname("vm.pagesize", &pagesize, &len, nullptr, 0) < 0) {
        throw std::system_error(errno,
                                std::system_category(),
                                R"(sysctlbyname("vm.pagesize"))");
    }

    mem.total = mem_total;
    mem.free = vmstat.free_count * pagesize;
    mem.used = mem.total - mem.free;

    uint64_t kern = vmstat.inactive_count * pagesize;
    mem.actual_free = mem.free + kern;
    mem.actual_used = mem.used - kern;
    mem_calc_ram(mem);

    return SIGAR_OK;
}

int AppleSigar::get_swap(sigar_swap_t& swap) {
    struct xsw_usage sw_usage;
    size_t size = sizeof(sw_usage);
    int mib[] = {CTL_VM, VM_SWAPUSAGE};

    if (sysctl(mib, NMIB(mib), &sw_usage, &size, nullptr, 0) != 0) {
        return errno;
    }

    swap.total = sw_usage.xsu_total;
    swap.used = sw_usage.xsu_used;
    swap.free = sw_usage.xsu_avail;

    const auto vmstat = get_vmstat();
    swap.page_in = vmstat.pageins;
    swap.page_out = vmstat.pageouts;

    return SIGAR_OK;
}

typedef unsigned long cp_time_t;

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

static const struct kinfo_proc* lookup_proc(const struct kinfo_proc* proc,
                                            int nproc,
                                            pid_t pid) {
    for (int i = 0; i < nproc; i++) {
        if (proc[i].kp_proc.p_pid == pid) {
            return proc + i;
        }
    }
    return NULL;
}

static int sigar_os_check_parents(const struct kinfo_proc* proc,
                                  int nproc,
                                  pid_t pid,
                                  pid_t ppid) {
    const struct kinfo_proc* p;
    do {
        p = lookup_proc(proc, nproc, pid);
        if (p == NULL) {
            return -1;
        }

        if (p->kp_eproc.e_ppid == ppid) {
            return SIGAR_OK;
        }
        pid = p->kp_eproc.e_ppid;
    } while (p->kp_eproc.e_ppid != 0);
    return -1;
}

#define tv2msec(tv) \
    (((uint64_t)tv.tv_sec * SIGAR_MSEC) + (((uint64_t)tv.tv_usec) / 1000))

void AppleSigar::iterate_child_processes(
        sigar_pid_t ppid, sigar::IterateChildProcessCallback callback) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int i, num;
    size_t len;
    struct kinfo_proc* proc;

    if (sysctl(mib, NMIB(mib), NULL, &len, NULL, 0) < 0) {
        throw std::system_error(
                errno,
                std::system_category(),
                "iterate_child_processes(): sysctl to determine size failed");
    }

    proc = (kinfo_proc*)malloc(len);

    if (sysctl(mib, NMIB(mib), proc, &len, NULL, 0) < 0) {
        free(proc);
        throw std::system_error(errno,
                                std::system_category(),
                                "iterate_child_processes(): sysctl failed");
    }

    num = len / sizeof(*proc);

    for (i = 0; i < num; i++) {
        if (sigar_os_check_parents(proc, num, proc[i].kp_proc.p_pid, ppid) ==
            SIGAR_OK) {
            callback(proc[i].kp_proc.p_pid,
                     proc[i].kp_eproc.e_ppid,
                     tv2msec(proc[i].kp_proc.p_starttime),
                     proc[i].kp_proc.p_comm);
        }
    }

    free(proc);
}

std::pair<int, kinfo_proc> AppleSigar::get_pinfo(sigar_pid_t pid) {
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, 0};
    mib[3] = pid;

    kinfo_proc pinfo = {};
    size_t len = sizeof(pinfo);

    if (sysctl(mib, NMIB(mib), &pinfo, &len, NULL, 0) < 0) {
        return {errno, {}};
    }

    return {SIGAR_OK, pinfo};
}

/* get the CPU type of the process for the given pid */
static int sigar_proc_cpu_type(sigar_pid_t pid, cpu_type_t* type) {
    int status;
    int mib[CTL_MAXNAME];
    size_t len, miblen = NMIB(mib);

    status = sysctlnametomib("sysctl.proc_cputype", mib, &miblen);
    if (status != SIGAR_OK) {
        return status;
    }

    mib[miblen] = pid;
    len = sizeof(*type);
    return sysctl(mib, miblen + 1, type, &len, NULL, 0);
}

/* shared memory region size for the given cpu_type_t */
static mach_vm_size_t sigar_shared_region_size(cpu_type_t type) {
    switch (type) {
    case CPU_TYPE_ARM:
        return SHARED_REGION_SIZE_ARM;
    case CPU_TYPE_POWERPC:
        return SHARED_REGION_SIZE_PPC;
    case CPU_TYPE_POWERPC64:
        return SHARED_REGION_SIZE_PPC64;
    case CPU_TYPE_I386:
        return SHARED_REGION_SIZE_I386;
    case CPU_TYPE_X86_64:
        return SHARED_REGION_SIZE_X86_64;
    default:
        return SHARED_REGION_SIZE_I386; /* assume 32-bit x86|ppc */
    }
}

int AppleSigar::get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem) {
    mach_port_t task, self = mach_task_self();
    kern_return_t status;
    task_basic_info_data_t info;
    task_events_info_data_t events;
    mach_msg_type_number_t count;
    struct proc_taskinfo pti;
    struct proc_regioninfo pri;

    int sz = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, sizeof(pti));
    if (sz == sizeof(pti)) {
        procmem.size = pti.pti_virtual_size;
        procmem.resident = pti.pti_resident_size;
        procmem.page_faults = pti.pti_faults;

        sz = proc_pidinfo(pid, PROC_PIDREGIONINFO, 0, &pri, sizeof(pri));
        if (sz == sizeof(pri)) {
            if (pri.pri_share_mode == SM_EMPTY) {
                mach_vm_size_t shared_size;
                cpu_type_t cpu_type;

                if (sigar_proc_cpu_type(pid, &cpu_type) == SIGAR_OK) {
                    shared_size = sigar_shared_region_size(cpu_type);
                } else {
                    shared_size =
                            SHARED_REGION_SIZE_I386; /* assume 32-bit x86|ppc */
                }
                if (procmem.size > shared_size) {
                    procmem.size -= shared_size; /* SIGAR-123 */
                }
            }
        }
        return SIGAR_OK;
    }

    status = task_for_pid(self, pid, &task);

    if (status != KERN_SUCCESS) {
        return errno;
    }

    count = TASK_BASIC_INFO_COUNT;
    status = task_info(task, TASK_BASIC_INFO, (task_info_t)&info, &count);
    if (status != KERN_SUCCESS) {
        return errno;
    }

    count = TASK_EVENTS_INFO_COUNT;
    status = task_info(task, TASK_EVENTS_INFO, (task_info_t)&events, &count);
    if (status == KERN_SUCCESS) {
        procmem.page_faults = events.faults;
    }

    if (task != self) {
        mach_port_deallocate(self, task);
    }

    procmem.size = info.virtual_size;
    procmem.resident = info.resident_size;

    return SIGAR_OK;
}

#define tval2msec(tval) \
    ((tval.seconds * SIGAR_MSEC) + (tval.microseconds / 1000))

#define tval2nsec(tval) \
    (SIGAR_SEC2NANO((tval).seconds) + SIGAR_MICROSEC2NANO((tval).microseconds))

static int get_proc_times(sigar_t* sigar,
                          sigar_pid_t pid,
                          sigar_proc_time_t* time) {
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
                     info.pth_name,
                     SIGAR_NSEC2USEC(info.pth_user_time),
                     SIGAR_NSEC2USEC(info.pth_system_time));
        }
    }

    vm_deallocate(self, (vm_address_t)threads, sizeof(thread_t) * count);
}
