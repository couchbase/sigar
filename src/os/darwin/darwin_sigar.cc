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

#include <dirent.h>
#include <errno.h>
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
#include <utility>

#define NMIB(mib) (sizeof(mib)/sizeof(mib[0]))

#define KI_FD   kp_proc.p_fd
#define KI_PID  kp_proc.p_pid
#define KI_PPID kp_eproc.e_ppid
#define KI_PRI  kp_proc.p_priority
#define KI_NICE kp_proc.p_nice
#define KI_COMM kp_proc.p_comm
#define KI_STAT kp_proc.p_stat
#define KI_UID  kp_eproc.e_pcred.p_ruid
#define KI_GID  kp_eproc.e_pcred.p_rgid
#define KI_EUID kp_eproc.e_pcred.p_svuid
#define KI_EGID kp_eproc.e_pcred.p_svgid
#define KI_SIZE XXX
#define KI_RSS  kp_eproc.e_vm.vm_rssize
#define KI_TSZ  kp_eproc.e_vm.vm_tsize
#define KI_DSZ  kp_eproc.e_vm.vm_dsize
#define KI_SSZ  kp_eproc.e_vm.vm_ssize
#define KI_FLAG kp_eproc.e_flag
#define KI_START kp_proc.p_starttime

#define SIGAR_PROC_STATE_SLEEP  'S'
#define SIGAR_PROC_STATE_RUN    'R'
#define SIGAR_PROC_STATE_STOP   'T'
#define SIGAR_PROC_STATE_ZOMBIE 'Z'
#define SIGAR_PROC_STATE_IDLE   'D'

sigar_t::sigar_t()
    : ticks(sysconf(_SC_CLK_TCK)),
      pagesize(getpagesize()),
      mach_port(mach_host_self()) {
}

sigar_t* sigar_t::New() {
    return new sigar_t;
}

static int sigar_vmstat(sigar_t *sigar, vm_statistics_data_t *vmstat)
{
    kern_return_t status;
    mach_msg_type_number_t count = sizeof(*vmstat) / sizeof(integer_t);

    status = host_statistics(sigar->mach_port, HOST_VM_INFO,
                             (host_info_t)vmstat, &count);

    if (status == KERN_SUCCESS) {
        return SIGAR_OK;
    }
    else {
        return errno;
    }
}

int sigar_t::get_memory(sigar_mem_t& mem) {
    uint64_t kern = 0;
    vm_statistics_data_t vmstat;
    uint64_t mem_total;
    int mib[2];
    size_t len;
    int status;

    mib[0] = CTL_HW;

    mib[1] = HW_PAGESIZE;
    len = sizeof(pagesize);
    if (sysctl(mib, NMIB(mib), &pagesize, &len, NULL, 0) < 0) {
        return errno;
    }

    mib[1] = HW_MEMSIZE;
    len = sizeof(mem_total);
    if (sysctl(mib, NMIB(mib), &mem_total, &len, NULL, 0) < 0) {
        return errno;
    }

    mem.total = mem_total;

    if ((status = sigar_vmstat(this, &vmstat)) != SIGAR_OK) {
        return status;
    }

    mem.free = vmstat.free_count;
    mem.free *= pagesize;
    kern = vmstat.inactive_count;
    kern *= pagesize;

    mem.used = mem.total - mem.free;

    mem.actual_free = mem.free + kern;
    mem.actual_used = mem.used - kern;
    mem_calc_ram(mem);

    return SIGAR_OK;
}

#define SWI_MAXMIB 3

#define getswapinfo_sysctl(swap_ary, swap_max) SIGAR_ENOTIMPL

#define SIGAR_FS_BLOCKS_TO_BYTES(val, bsize) ((val * bsize) >> 1)

#define VM_DIR "/private/var/vm"
#define SWAPFILE "swapfile"

static int sigar_swap_fs_get(sigar_t *sigar, sigar_swap_t *swap) /* <= 10.3 */
{
    DIR *dirp;
    struct dirent *ent;
    char swapfile[SSTRLEN(VM_DIR) + SSTRLEN("/") + SSTRLEN(SWAPFILE) + 12];
    struct stat swapstat;
    struct statfs vmfs;
    uint64_t val, bsize;

    swap->used = swap->total = swap->free = 0;

    if (!(dirp = opendir(VM_DIR))) {
         return errno;
     }

    /* looking for "swapfile0", "swapfile1", etc. */
    while ((ent = readdir(dirp))) {
        char *ptr = swapfile;

        if ((ent->d_namlen < SSTRLEN(SWAPFILE)+1) || /* n/a, see comment above */
            (ent->d_namlen > SSTRLEN(SWAPFILE)+11)) /* ensure no overflow */
        {
            continue;
        }

        if (!strnEQ(ent->d_name, SWAPFILE, SSTRLEN(SWAPFILE))) {
            continue;
        }

        /* sprintf(swapfile, "%s/%s", VM_DIR, ent->d_name) */

        memcpy(ptr, VM_DIR, SSTRLEN(VM_DIR));
        ptr += SSTRLEN(VM_DIR);

        *ptr++ = '/';

        memcpy(ptr, ent->d_name, ent->d_namlen+1);

        if (stat(swapfile, &swapstat) < 0) {
            continue;
        }

        swap->used += swapstat.st_size;
    }

    closedir(dirp);

    if (statfs(VM_DIR, &vmfs) < 0) {
        return errno;
    }

    bsize = vmfs.f_bsize / 512;
    val = vmfs.f_bfree;
    swap->total = SIGAR_FS_BLOCKS_TO_BYTES(val, bsize) + swap->used;

    swap->free = swap->total - swap->used;

    return SIGAR_OK;
}

static int sigar_swap_sysctl_get(sigar_t *sigar, sigar_swap_t *swap)

{
    struct xsw_usage sw_usage;
    size_t size = sizeof(sw_usage);
    int mib[] = { CTL_VM, VM_SWAPUSAGE };

    if (sysctl(mib, NMIB(mib), &sw_usage, &size, NULL, 0) != 0) {
        return errno;
    }

    swap->total = sw_usage.xsu_total;
    swap->used = sw_usage.xsu_used;
    swap->free = sw_usage.xsu_avail;

    return SIGAR_OK;
}

int sigar_t::get_swap(sigar_swap_t& swap) {
    int status;
    vm_statistics_data_t vmstat;

    if (sigar_swap_sysctl_get(this, &swap) != SIGAR_OK) {
        status = sigar_swap_fs_get(this, &swap); /* <= 10.3 */
        if (status != SIGAR_OK) {
            return status;
        }
    }

    if ((status = sigar_vmstat(this, &vmstat)) != SIGAR_OK) {
        return status;
    }
    swap.page_in = vmstat.pageins;
    swap.page_out = vmstat.pageouts;

    return SIGAR_OK;
}

typedef unsigned long cp_time_t;

int sigar_t::get_cpu(sigar_cpu_t& cpu) {
    kern_return_t status;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    host_cpu_load_info_data_t cpuload;

    status = host_statistics(mach_port, HOST_CPU_LOAD_INFO,
                             (host_info_t)&cpuload, &count);

    if (status != KERN_SUCCESS) {
        return errno;
    }

    sigar_t* sigar = this;
    cpu.user = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_USER]);
    cpu.sys = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_SYSTEM]);
    cpu.idle = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_IDLE]);
    cpu.nice = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_NICE]);
    cpu.total = cpu.user + cpu.nice + cpu.sys + cpu.idle;

    return SIGAR_OK;
}

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist)
{
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    int i, num;
    size_t len;
    struct kinfo_proc *proc;

    if (sysctl(mib, NMIB(mib), NULL, &len, NULL, 0) < 0) {
        return errno;
    }

    proc = (kinfo_proc *)malloc(len);

    if (sysctl(mib, NMIB(mib), proc, &len, NULL, 0) < 0) {
        free(proc);
        return errno;
    }

    num = len/sizeof(*proc);

    uid_t me = getuid();

    for (i=0; i<num; i++) {
        if (proc[i].KI_FLAG & P_SYSTEM) {
            continue;
        }
        if (proc[i].KI_PID == 0) {
            continue;
        }

        if (proc[i].KI_UID != me) {
            continue;
        }

        SIGAR_PROC_LIST_GROW(proclist);
        proclist->data[proclist->number++] = proc[i].KI_PID;
    }

    free(proc);

    return SIGAR_OK;
}

static const struct kinfo_proc* lookup_proc(const struct kinfo_proc* proc,
                                            int nproc,
                                            pid_t pid) {
    for (int  i = 0; i < nproc; i++) {
        if (proc[i].KI_PID == pid) {
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

        if (p->KI_PPID == ppid) {
            return SIGAR_OK;
        }
        pid = p->KI_PPID;
    } while (p->KI_PPID != 0);
    return -1;
}

int sigar_os_proc_list_get_children(sigar_t* sigar,
                                    sigar_pid_t ppid,
                                    sigar_proc_list_t* proclist) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int i, num;
    size_t len;
    struct kinfo_proc* proc;

    if (sysctl(mib, NMIB(mib), NULL, &len, NULL, 0) < 0) {
        return errno;
    }

    proc = (kinfo_proc *)malloc(len);

    if (sysctl(mib, NMIB(mib), proc, &len, NULL, 0) < 0) {
        free(proc);
        return errno;
    }

    num = len / sizeof(*proc);

    for (i = 0; i < num; i++) {
        if (sigar_os_check_parents(proc, num, proc[i].KI_PID, ppid) ==
            SIGAR_OK) {
            SIGAR_PROC_LIST_GROW(proclist);
            proclist->data[proclist->number++] = proc[i].KI_PID;
        }
    }

    free(proc);

    return SIGAR_OK;
}

static std::pair<int, kinfo_proc> sigar_get_pinfo(sigar_t* sigar,
                                                  sigar_pid_t pid) {
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    mib[3] = pid;

    kinfo_proc pinfo = {};
    size_t len = sizeof(pinfo);

    if (sysctl(mib, NMIB(mib), &pinfo, &len, NULL, 0) < 0) {
        return {errno, {}};
    }

    return {SIGAR_OK, pinfo};
}

/* get the CPU type of the process for the given pid */
static int sigar_proc_cpu_type(sigar_t *sigar, sigar_pid_t pid, cpu_type_t *type)
{
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
static mach_vm_size_t sigar_shared_region_size(cpu_type_t type)
{
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

int sigar_t::get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem) {
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

                if (sigar_proc_cpu_type(this, pid, &cpu_type) == SIGAR_OK) {
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

#define tv2msec(tv) \
   (((uint64_t)tv.tv_sec * SIGAR_MSEC) + (((uint64_t)tv.tv_usec) / 1000))

#define tval2msec(tval) \
   ((tval.seconds * SIGAR_MSEC) + (tval.microseconds / 1000))

#define tval2nsec(tval) \
    (SIGAR_SEC2NANO((tval).seconds) + SIGAR_MICROSEC2NANO((tval).microseconds))

static int get_proc_times(sigar_t *sigar, sigar_pid_t pid, sigar_proc_time_t *time)
{
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
        time->sys  = SIGAR_NSEC2MSEC(pti.pti_total_system);
        time->total = time->user + time->sys;
        return SIGAR_OK;
    }

    self = mach_task_self();
    status = task_for_pid(self, pid, &task);
    if (status != KERN_SUCCESS) {
        return errno;
    }

    count = TASK_BASIC_INFO_COUNT;
    status = task_info(task, TASK_BASIC_INFO,
                       (task_info_t)&ti, &count);
    if (status != KERN_SUCCESS) {
        if (task != self) {
            mach_port_deallocate(self, task);
        }
        return errno;
    }

    count = TASK_THREAD_TIMES_INFO_COUNT;
    status = task_info(task, TASK_THREAD_TIMES_INFO,
                       (task_info_t)&tti, &count);
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
    time->sys  = tval2msec(stime);
    time->total = time->user + time->sys;

    return SIGAR_OK;
}

int sigar_t::get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime) {
    const auto [status, pinfo] = sigar_get_pinfo(this, pid);
    if (status != SIGAR_OK) {
        return status;
    }

    int st = get_proc_times(this, pid, &proctime);
    if (st != SIGAR_OK) {
        return st;
    }

    proctime.start_time = tv2msec(pinfo.KI_START);
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
    /*7*/ '?'
};

static int thread_state_get(thread_basic_info_data_t *info)
{
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

static int sigar_proc_threads_get(sigar_t *sigar, sigar_pid_t pid,
                                  sigar_proc_state_t *procstate)
{
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

    procstate->threads = count;

    for (i=0; i<count; i++) {
        mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;
        thread_basic_info_data_t info;

        status = thread_info(threads[i], THREAD_BASIC_INFO,
                             (thread_info_t)&info, &info_count);
        if (status == KERN_SUCCESS) {
            int tstate = thread_state_get(&info);
            if (tstate < state) {
                state = tstate;
            }
        }
    }

    vm_deallocate(self, (vm_address_t)threads, sizeof(thread_t) * count);

    procstate->state = thread_states[state];

    return SIGAR_OK;
}

int sigar_t::get_proc_state(sigar_pid_t pid, sigar_proc_state_t& procstate) {
    const auto [status, pinfo] = sigar_get_pinfo(this, pid);
    if (status != SIGAR_OK) {
        return status;
    }
    int state = pinfo.KI_STAT;

    SIGAR_SSTRCPY(procstate.name, pinfo.KI_COMM);
    procstate.ppid = pinfo.KI_PPID;
    procstate.priority = pinfo.KI_PRI;
    procstate.nice = pinfo.KI_NICE;

    auto st = sigar_proc_threads_get(this, pid, &procstate);
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
