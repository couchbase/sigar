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
#include "sigar_util.h"
#include "sigar_os.h"

#include <unistd.h>
#include <sys/param.h>
#include <sys/mount.h>
#if !(defined(__FreeBSD__) && (__FreeBSD_version >= 800000))
#include <nfs/rpcv2.h>
#endif
#include <nfs/nfsproto.h>

#ifdef DARWIN
#include <dlfcn.h>
#include <mach/mach_init.h>
#include <mach/message.h>
#include <mach/kern_return.h>
#include <mach/mach_host.h>
#include <mach/mach_traps.h>
#include <mach/mach_port.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#if !defined(HAVE_SHARED_REGION_H) && defined(__MAC_10_5) /* see Availability.h */
#  define HAVE_SHARED_REGION_H /* suckit autoconf */
#endif
#ifdef HAVE_SHARED_REGION_H
#include <mach/shared_region.h> /* does not exist in 10.4 SDK */
#else
#include <mach/shared_memory_server.h> /* deprecated in Leopard */
#endif
#include <mach-o/dyld.h>
#define __OPENTRANSPORTPROVIDERS__
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOTypes.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#else
#include <sys/dkstat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/vmmeter.h>
#include <fcntl.h>
#include <stdio.h>
#endif

#if defined(__FreeBSD__) && (__FreeBSD_version >= 500013)
#define SIGAR_FREEBSD5_NFSSTAT
#include <nfsclient/nfs.h>
#include <nfsserver/nfs.h>
#else
#include <nfs/nfs.h>
#endif

#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <dirent.h>
#include <errno.h>

#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#ifdef __NetBSD__
#include <netinet/ip_var.h>
#include <sys/lwp.h>
#include <sys/mount.h>
#define SRUN LSRUN
#define SSLEEP LSSLEEP
#define SDEAD LSDEAD
#define SONPROC LSONPROC
#define SSUSPENDED LSSUSPENDED
#include <sys/sched.h>
#endif
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>

#define NMIB(mib) (sizeof(mib)/sizeof(mib[0]))

#ifdef __FreeBSD__
#  if (__FreeBSD_version >= 500013)
#    define SIGAR_FREEBSD5
#  else
#    define SIGAR_FREEBSD4
#  endif
#endif

#if defined(SIGAR_FREEBSD5)

#define KI_FD   ki_fd
#define KI_PID  ki_pid
#define KI_PPID ki_ppid
#define KI_PRI  ki_pri.pri_user
#define KI_NICE ki_nice
#define KI_COMM ki_comm
#define KI_STAT ki_stat
#define KI_UID  ki_ruid
#define KI_GID  ki_rgid
#define KI_EUID ki_svuid
#define KI_EGID ki_svgid
#define KI_SIZE ki_size
#define KI_RSS  ki_rssize
#define KI_TSZ  ki_tsize
#define KI_DSZ  ki_dsize
#define KI_SSZ  ki_ssize
#define KI_FLAG ki_flag
#define KI_START ki_start

#elif defined(DARWIN) || defined(SIGAR_FREEBSD4) || defined(__OpenBSD__) || defined(__NetBSD__)

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

#endif

#ifndef DARWIN

#define PROCFS_STATUS(status) \
    ((((status) != SIGAR_OK) && !sigar->proc_mounted) ? \
     SIGAR_ENOTIMPL : status)

static int get_koffsets(sigar_t *sigar)
{
    int i;
    struct nlist klist[] = {
        { "_cp_time" },
        { "_cnt" },
#if defined(__OpenBSD__) || defined(__NetBSD__)
        { "_tcpstat" },
        { "_tcbtable" },
#endif
        { NULL }
    };

    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    kvm_nlist(sigar->kmem, klist);

    for (i=0; i<KOFFSET_MAX; i++) {
        sigar->koffsets[i] = klist[i].n_value;
    }

    return SIGAR_OK;
}

static int kread(sigar_t *sigar, void *data, int size, long offset)
{
    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    if (kvm_read(sigar->kmem, offset, data, size) != size) {
        return errno;
    }

    return SIGAR_OK;
}
#endif

int sigar_os_open(sigar_t **sigar)
{
    int mib[2];
    int ncpu;
    size_t len;
    struct timeval boottime;
#ifndef DARWIN
    struct stat sb;
#endif

    len = sizeof(ncpu);
    mib[0] = CTL_HW;
    mib[1] = HW_NCPU;
    if (sysctl(mib, NMIB(mib), &ncpu,  &len, NULL, 0) < 0) {
        return errno;
    }

    len = sizeof(boottime);
    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;
    if (sysctl(mib, NMIB(mib), &boottime, &len, NULL, 0) < 0) {
        return errno;
    }

    *sigar = malloc(sizeof(**sigar));

#ifdef DARWIN
    (*sigar)->mach_port = mach_host_self();
#  ifdef DARWIN_HAS_LIBPROC_H
    if (((*sigar)->libproc = dlopen("/usr/lib/libproc.dylib", 0))) {
        (*sigar)->proc_pidinfo =
                (proc_pidinfo_func_t)dlsym((*sigar)->libproc, "proc_pidinfo");
        (*sigar)->proc_pidfdinfo = (proc_pidfdinfo_func_t)dlsym(
                (*sigar)->libproc, "proc_pidfdinfo");
    }
#  endif
#else
    (*sigar)->kmem = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);
    if (stat("/proc/curproc", &sb) < 0) {
        (*sigar)->proc_mounted = 0;
    }
    else {
        (*sigar)->proc_mounted = 1;
    }
#endif

#ifndef DARWIN
    get_koffsets(*sigar);
#endif

    (*sigar)->ncpu = ncpu;
    (*sigar)->lcpu = -1;
    (*sigar)->argmax = 0;
    (*sigar)->boot_time = boottime.tv_sec; /* XXX seems off a bit */

    (*sigar)->pagesize = getpagesize();
#ifdef __FreeBSD__
    (*sigar)->ticks = 100; /* sysconf(_SC_CLK_TCK) == 128 !? */
#else
    (*sigar)->ticks = sysconf(_SC_CLK_TCK);
#endif
    (*sigar)->last_pid = -1;

    (*sigar)->pinfo = NULL;

    return SIGAR_OK;
}

int sigar_os_close(sigar_t *sigar)
{
    if (sigar->pinfo) {
        free(sigar->pinfo);
    }
#ifndef DARWIN
    if (sigar->kmem) {
        kvm_close(sigar->kmem);
    }
#endif
    free(sigar);
    return SIGAR_OK;
}

char *sigar_os_error_string(sigar_t *sigar, int err)
{
    switch (err) {
      case SIGAR_EPERM_KMEM:
        return "Failed to open /dev/kmem for reading";
      case SIGAR_EPROC_NOENT:
        return "/proc filesystem is not mounted";
      default:
        return NULL;
    }
}

#if defined(DARWIN)
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
#elif defined(__FreeBSD__)
static int sigar_vmstat(sigar_t *sigar, struct vmmeter *vmstat)
{
    int status;
    size_t size = sizeof(unsigned int);

    status = kread(sigar, vmstat, sizeof(*vmstat),
                   sigar->koffsets[KOFFSET_VMMETER]);

    if (status == SIGAR_OK) {
        return SIGAR_OK;
    }

    SIGAR_ZERO(vmstat);

    /* derived from src/usr.bin/vmstat/vmstat.c */
    /* only collect the ones we actually use */
#define GET_VM_STATS(cat, name, used) \
    if (used) sysctlbyname("vm.stats." #cat "." #name, &vmstat->name, &size, NULL, 0)

    /* sys */
    GET_VM_STATS(sys, v_swtch, 0);
    GET_VM_STATS(sys, v_trap, 0);
    GET_VM_STATS(sys, v_syscall, 0);
    GET_VM_STATS(sys, v_intr, 0);
    GET_VM_STATS(sys, v_soft, 0);

    /* vm */
    GET_VM_STATS(vm, v_vm_faults, 0);
    GET_VM_STATS(vm, v_cow_faults, 0);
    GET_VM_STATS(vm, v_cow_optim, 0);
    GET_VM_STATS(vm, v_zfod, 0);
    GET_VM_STATS(vm, v_ozfod, 0);
    GET_VM_STATS(vm, v_swapin, 1);
    GET_VM_STATS(vm, v_swapout, 1);
    GET_VM_STATS(vm, v_swappgsin, 0);
    GET_VM_STATS(vm, v_swappgsout, 0);
    GET_VM_STATS(vm, v_vnodein, 1);
    GET_VM_STATS(vm, v_vnodeout, 1);
    GET_VM_STATS(vm, v_vnodepgsin, 0);
    GET_VM_STATS(vm, v_vnodepgsout, 0);
    GET_VM_STATS(vm, v_intrans, 0);
    GET_VM_STATS(vm, v_reactivated, 0);
    GET_VM_STATS(vm, v_pdwakeups, 0);
    GET_VM_STATS(vm, v_pdpages, 0);
    GET_VM_STATS(vm, v_dfree, 0);
    GET_VM_STATS(vm, v_pfree, 0);
    GET_VM_STATS(vm, v_tfree, 0);
    GET_VM_STATS(vm, v_page_size, 0);
    GET_VM_STATS(vm, v_page_count, 0);
    GET_VM_STATS(vm, v_free_reserved, 0);
    GET_VM_STATS(vm, v_free_target, 0);
    GET_VM_STATS(vm, v_free_min, 0);
    GET_VM_STATS(vm, v_free_count, 1);
    GET_VM_STATS(vm, v_wire_count, 0);
    GET_VM_STATS(vm, v_active_count, 0);
    GET_VM_STATS(vm, v_inactive_target, 0);
    GET_VM_STATS(vm, v_inactive_count, 1);
    GET_VM_STATS(vm, v_cache_count, 1);
#if (__FreeBSD_version < 1100079 )
    GET_VM_STATS(vm, v_cache_min, 0);
    GET_VM_STATS(vm, v_cache_max, 0);
#endif
    GET_VM_STATS(vm, v_pageout_free_min, 0);
    GET_VM_STATS(vm, v_interrupt_free_min, 0);
    GET_VM_STATS(vm, v_forks, 0);
    GET_VM_STATS(vm, v_vforks, 0);
    GET_VM_STATS(vm, v_rforks, 0);
    GET_VM_STATS(vm, v_kthreads, 0);
    GET_VM_STATS(vm, v_forkpages, 0);
    GET_VM_STATS(vm, v_vforkpages, 0);
    GET_VM_STATS(vm, v_rforkpages, 0);
    GET_VM_STATS(vm, v_kthreadpages, 0);
#undef GET_VM_STATS

    return SIGAR_OK;
}
#elif defined(__OpenBSD__) || defined(__NetBSD__)
static int sigar_vmstat(sigar_t *sigar, struct uvmexp *vmstat)
{
    size_t size = sizeof(*vmstat);
    int mib[] = { CTL_VM, VM_UVMEXP };
    if (sysctl(mib, NMIB(mib), vmstat, &size, NULL, 0) < 0) {
        return errno;
    }
    else {
        return SIGAR_OK;
    }
}
#endif

int sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem)
{
    sigar_uint64_t kern = 0;
#ifdef DARWIN
    vm_statistics_data_t vmstat;
    uint64_t mem_total;
#else
    unsigned long mem_total;
#endif
#if defined(__FreeBSD__)
    struct vmmeter vmstat;
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    struct uvmexp vmstat;
#endif
    int mib[2];
    size_t len;
    int status;

    mib[0] = CTL_HW;

    mib[1] = HW_PAGESIZE;
    len = sizeof(sigar->pagesize);
    if (sysctl(mib, NMIB(mib), &sigar->pagesize, &len, NULL, 0) < 0) {
        return errno;
    }

#ifdef DARWIN
    mib[1] = HW_MEMSIZE;
#else
    mib[1] = HW_PHYSMEM;
#endif
    len = sizeof(mem_total);
    if (sysctl(mib, NMIB(mib), &mem_total, &len, NULL, 0) < 0) {
        return errno;
    }

    mem->total = mem_total;

#if defined(DARWIN)
    if ((status = sigar_vmstat(sigar, &vmstat)) != SIGAR_OK) {
        return status;
    }

    mem->free = vmstat.free_count;
    mem->free *= sigar->pagesize;
    kern = vmstat.inactive_count;
    kern *= sigar->pagesize;
#elif defined(__FreeBSD__)
    if ((status = sigar_vmstat(sigar, &vmstat)) == SIGAR_OK) {
        kern = vmstat.v_cache_count + vmstat.v_inactive_count;
        kern *= sigar->pagesize;
        mem->free = vmstat.v_free_count;
        mem->free *= sigar->pagesize;
    }
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    if ((status = sigar_vmstat(sigar, &vmstat)) != SIGAR_OK) {
        return status;
    }
    mem->free = vmstat.free;
    kern = vmstat.inactive;
#  if defined(__OpenBSD__)
    kern += vmstat.vnodepages + vmstat.vtextpages;
# elif defined(__NetBSD__)
    kern += vmstat.filepages + vmstat.execpages;
#  endif
    kern *= sigar->pagesize;
#endif

    mem->used = mem->total - mem->free;

    mem->actual_free = mem->free + kern;
    mem->actual_used = mem->used - kern;

    sigar_mem_calc_ram(sigar, mem);

    return SIGAR_OK;
}

#define SWI_MAXMIB 3

#ifdef SIGAR_FREEBSD5
/* code in this function is based on FreeBSD 5.3 kvm_getswapinfo.c */
static int getswapinfo_sysctl(struct kvm_swap *swap_ary,
                              int swap_max)
{
    int ti, ttl;
    size_t mibi, len, size;
    int soid[SWI_MAXMIB];
    struct xswdev xsd;
    struct kvm_swap tot;
    int unswdev, dmmax;

    /* XXX this can be optimized by using os_open */
    size = sizeof(dmmax);
    if (sysctlbyname("vm.dmmax", &dmmax, &size, NULL, 0) == -1) {
        return errno;
    }

    mibi = SWI_MAXMIB - 1;
    if (sysctlnametomib("vm.swap_info", soid, &mibi) == -1) {
        return errno;
    }

    bzero(&tot, sizeof(tot));
    for (unswdev = 0;; unswdev++) {
        soid[mibi] = unswdev;
        len = sizeof(xsd);
        if (sysctl(soid, mibi + 1, &xsd, &len, NULL, 0) == -1) {
            if (errno == ENOENT) {
                break;
            }
            return errno;
        }
#if 0
        if (len != sizeof(xsd)) {
            _kvm_err(kd, kd->program, "struct xswdev has unexpected "
                     "size;  kernel and libkvm out of sync?");
            return -1;
        }
        if (xsd.xsw_version != XSWDEV_VERSION) {
            _kvm_err(kd, kd->program, "struct xswdev version "
                     "mismatch; kernel and libkvm out of sync?");
            return -1;
        }
#endif
        ttl = xsd.xsw_nblks - dmmax;
        if (unswdev < swap_max - 1) {
            bzero(&swap_ary[unswdev], sizeof(swap_ary[unswdev]));
            swap_ary[unswdev].ksw_total = ttl;
            swap_ary[unswdev].ksw_used = xsd.xsw_used;
            swap_ary[unswdev].ksw_flags = xsd.xsw_flags;
        }
        tot.ksw_total += ttl;
        tot.ksw_used += xsd.xsw_used;
    }

    ti = unswdev;
    if (ti >= swap_max) {
        ti = swap_max - 1;
    }
    if (ti >= 0) {
        swap_ary[ti] = tot;
    }

    return SIGAR_OK;
}
#else
#define getswapinfo_sysctl(swap_ary, swap_max) SIGAR_ENOTIMPL
#endif

#define SIGAR_FS_BLOCKS_TO_BYTES(val, bsize) ((val * bsize) >> 1)

#ifdef DARWIN
#define VM_DIR "/private/var/vm"
#define SWAPFILE "swapfile"

static int sigar_swap_fs_get(sigar_t *sigar, sigar_swap_t *swap) /* <= 10.3 */
{
    DIR *dirp;
    struct dirent *ent;
    char swapfile[SSTRLEN(VM_DIR) + SSTRLEN("/") + SSTRLEN(SWAPFILE) + 12];
    struct stat swapstat;
    struct statfs vmfs;
    sigar_uint64_t val, bsize;

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
#ifdef VM_SWAPUSAGE /* => 10.4 */
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
#else
    return SIGAR_ENOTIMPL; /* <= 10.3 */
#endif
}
#endif /* DARWIN */

int sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap)
{
    int status;
#if defined(DARWIN)
    vm_statistics_data_t vmstat;

    if (sigar_swap_sysctl_get(sigar, swap) != SIGAR_OK) {
        status = sigar_swap_fs_get(sigar, swap); /* <= 10.3 */
        if (status != SIGAR_OK) {
            return status;
        }
    }

    if ((status = sigar_vmstat(sigar, &vmstat)) != SIGAR_OK) {
        return status;
    }
    swap->page_in = vmstat.pageins;
    swap->page_out = vmstat.pageouts;
#elif defined(__FreeBSD__)
    struct kvm_swap kswap[1];
    struct vmmeter vmstat;

    if (getswapinfo_sysctl(kswap, 1) != SIGAR_OK) {
        if (!sigar->kmem) {
            return SIGAR_EPERM_KMEM;
        }

        if (kvm_getswapinfo(sigar->kmem, kswap, 1, 0) < 0) {
            return errno;
        }
    }

    if (kswap[0].ksw_total == 0) {
        swap->total = 0;
        swap->used  = 0;
        swap->free  = 0;
        return SIGAR_OK;
    }

    swap->total = kswap[0].ksw_total * sigar->pagesize;
    swap->used  = kswap[0].ksw_used * sigar->pagesize;
    swap->free  = swap->total - swap->used;

    if ((status = sigar_vmstat(sigar, &vmstat)) == SIGAR_OK) {
        swap->page_in = vmstat.v_swapin + vmstat.v_vnodein;
        swap->page_out = vmstat.v_swapout + vmstat.v_vnodeout;
    }
    else {
        swap->page_in = swap->page_out = -1;
    }
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    struct uvmexp vmstat;

    if ((status = sigar_vmstat(sigar, &vmstat)) != SIGAR_OK) {
        return status;
    }
    swap->total = vmstat.swpages * sigar->pagesize;
    swap->used = vmstat.swpginuse * sigar->pagesize;
    swap->free  = swap->total - swap->used;
    swap->page_in = vmstat.pageins;
    swap->page_out = vmstat.pdpageouts;
#endif

    return SIGAR_OK;
}

#ifndef KERN_CPTIME
#define KERN_CPTIME KERN_CP_TIME
#endif

#if defined(__NetBSD__)
typedef uint64_t cp_time_t;
#else
typedef unsigned long cp_time_t;
#endif

int sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
#if defined(DARWIN)
    kern_return_t status;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    host_cpu_load_info_data_t cpuload;

    status = host_statistics(sigar->mach_port, HOST_CPU_LOAD_INFO,
                             (host_info_t)&cpuload, &count);

    if (status != KERN_SUCCESS) {
        return errno;
    }

    cpu->user = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_USER]);
    cpu->sys  = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_SYSTEM]);
    cpu->idle = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_IDLE]);
    cpu->nice = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_NICE]);
    cpu->wait = 0; /*N/A*/
    cpu->irq = 0; /*N/A*/
    cpu->soft_irq = 0; /*N/A*/
    cpu->stolen = 0; /*N/A*/
    cpu->total = cpu->user + cpu->nice + cpu->sys + cpu->idle;

#elif defined(__FreeBSD__) || (__OpenBSD__) || defined(__NetBSD__)
    int status;
    cp_time_t cp_time[CPUSTATES];
    size_t size = sizeof(cp_time);

#  if defined(__OpenBSD__) || defined(__NetBSD__)
    int mib[] = { CTL_KERN, KERN_CPTIME };
    if (sysctl(mib, NMIB(mib), &cp_time, &size, NULL, 0) == -1) {
        status = errno;
    }
#  else
    /* try sysctl first, does not require /dev/kmem perms */
    if (sysctlbyname("kern.cp_time", &cp_time, &size, NULL, 0) == -1) {
        status = kread(sigar, &cp_time, sizeof(cp_time),
                       sigar->koffsets[KOFFSET_CPUINFO]);
    }
#  endif
    else {
        status = SIGAR_OK;
    }

    if (status != SIGAR_OK) {
        return status;
    }

    cpu->user = SIGAR_TICK2MSEC(cp_time[CP_USER]);
    cpu->nice = SIGAR_TICK2MSEC(cp_time[CP_NICE]);
    cpu->sys  = SIGAR_TICK2MSEC(cp_time[CP_SYS]);
    cpu->idle = SIGAR_TICK2MSEC(cp_time[CP_IDLE]);
    cpu->wait = 0; /*N/A*/
    cpu->irq = SIGAR_TICK2MSEC(cp_time[CP_INTR]);
    cpu->soft_irq = 0; /*N/A*/
    cpu->stolen = 0; /*N/A*/
    cpu->total = cpu->user + cpu->nice + cpu->sys + cpu->idle + cpu->irq;
#endif

    return SIGAR_OK;
}

#ifndef KERN_PROC_PROC
/* freebsd 4.x */
#define KERN_PROC_PROC KERN_PROC_ALL
#endif

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist)
{
#if defined(DARWIN) || defined(SIGAR_FREEBSD5) || defined(__OpenBSD__) || defined(__NetBSD__)
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0 };
    int i, num;
    size_t len;
    struct kinfo_proc *proc;

    if (sysctl(mib, NMIB(mib), NULL, &len, NULL, 0) < 0) {
        return errno;
    }

    proc = malloc(len);

    if (sysctl(mib, NMIB(mib), proc, &len, NULL, 0) < 0) {
        free(proc);
        return errno;
    }

    num = len/sizeof(*proc);

    sigar_uid_t me = getuid();

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
#else
    int i, num;
    struct kinfo_proc *proc;

    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    proc = kvm_getprocs(sigar->kmem, KERN_PROC_PROC, 0, &num);

    for (i=0; i<num; i++) {
        if (proc[i].KI_FLAG & P_SYSTEM) {
            continue;
        }
        SIGAR_PROC_LIST_GROW(proclist);
        proclist->data[proclist->number++] = proc[i].KI_PID;
    }
#endif

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
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    int i, num;
    size_t len;
    struct kinfo_proc* proc;

    if (sysctl(mib, NMIB(mib), NULL, &len, NULL, 0) < 0) {
        return errno;
    }

    proc = malloc(len);

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

static int sigar_get_pinfo(sigar_t *sigar, sigar_pid_t pid)
{
#if defined(__OpenBSD__) || defined(__NetBSD__)
    int mib[] = { CTL_KERN, KERN_PROC2, KERN_PROC_PID, 0, sizeof(*sigar->pinfo), 1 };
#else
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
#endif
    size_t len = sizeof(*sigar->pinfo);
    time_t timenow = time(NULL);
    mib[3] = pid;

    if (sigar->pinfo == NULL) {
        sigar->pinfo = malloc(len);
    }

    if (sigar->last_pid == pid) {
        if ((timenow - sigar->last_getprocs) < SIGAR_LAST_PROC_EXPIRE) {
            return SIGAR_OK;
        }
    }

    sigar->last_pid = pid;
    sigar->last_getprocs = timenow;

    if (sysctl(mib, NMIB(mib), sigar->pinfo, &len, NULL, 0) < 0) {
        return errno;
    }

    return SIGAR_OK;
}

#if defined(SHARED_TEXT_REGION_SIZE) && defined(SHARED_DATA_REGION_SIZE)
#  define GLOBAL_SHARED_SIZE (SHARED_TEXT_REGION_SIZE + SHARED_DATA_REGION_SIZE) /* 10.4 SDK */
#endif

#if defined(DARWIN) && defined(DARWIN_HAS_LIBPROC_H) && !defined(GLOBAL_SHARED_SIZE)
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
#endif /* DARWIN */

int sigar_proc_mem_get(sigar_t *sigar, sigar_pid_t pid,
                       sigar_proc_mem_t *procmem)
{
#if defined(DARWIN)
    mach_port_t task, self = mach_task_self();
    kern_return_t status;
    task_basic_info_data_t info;
    task_events_info_data_t events;
    mach_msg_type_number_t count;
#  ifdef DARWIN_HAS_LIBPROC_H
    struct proc_taskinfo pti;
    struct proc_regioninfo pri;

    if (sigar->libproc) {
        int sz =
            sigar->proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, sizeof(pti));

        if (sz == sizeof(pti)) {
            procmem->size         = pti.pti_virtual_size;
            procmem->resident     = pti.pti_resident_size;
            procmem->page_faults  = pti.pti_faults;
            procmem->minor_faults = SIGAR_FIELD_NOTIMPL;
            procmem->major_faults = SIGAR_FIELD_NOTIMPL;
            procmem->share        = SIGAR_FIELD_NOTIMPL;

            sz = sigar->proc_pidinfo(pid, PROC_PIDREGIONINFO, 0, &pri, sizeof(pri));
            if (sz == sizeof(pri)) {
                if (pri.pri_share_mode == SM_EMPTY) {
                    mach_vm_size_t shared_size;
#ifdef GLOBAL_SHARED_SIZE
                    shared_size = GLOBAL_SHARED_SIZE; /* 10.4 SDK */
#else
                    cpu_type_t cpu_type;

                    if (sigar_proc_cpu_type(sigar, pid, &cpu_type) == SIGAR_OK) {
                        shared_size = sigar_shared_region_size(cpu_type);
                    }
                    else {
                        shared_size = SHARED_REGION_SIZE_I386; /* assume 32-bit x86|ppc */
                    }
#endif
                    if (procmem->size > shared_size) {
                        procmem->size -= shared_size; /* SIGAR-123 */
                    }
                }
            }
            return SIGAR_OK;
        }
    }
#  endif

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
        procmem->page_faults = events.faults;
    }
    else {
        procmem->page_faults = SIGAR_FIELD_NOTIMPL;
    }

    procmem->minor_faults = SIGAR_FIELD_NOTIMPL;
    procmem->major_faults = SIGAR_FIELD_NOTIMPL;

    if (task != self) {
        mach_port_deallocate(self, task);
    }

    procmem->size     = info.virtual_size;
    procmem->resident = info.resident_size;
    procmem->share    = SIGAR_FIELD_NOTIMPL;

    return SIGAR_OK;
#elif defined(__FreeBSD__)
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    procmem->size =
        (pinfo->KI_TSZ + pinfo->KI_DSZ + pinfo->KI_SSZ) * sigar->pagesize;

    procmem->resident = pinfo->KI_RSS * sigar->pagesize;

    procmem->share = SIGAR_FIELD_NOTIMPL;

    procmem->page_faults  = SIGAR_FIELD_NOTIMPL;
    procmem->minor_faults = SIGAR_FIELD_NOTIMPL;
    procmem->major_faults = SIGAR_FIELD_NOTIMPL;
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    procmem->size =
        (pinfo->p_vm_tsize + pinfo->p_vm_dsize + pinfo->p_vm_ssize) * sigar->pagesize;

    procmem->resident = pinfo->p_vm_rssize * sigar->pagesize;

    procmem->share = SIGAR_FIELD_NOTIMPL;

    procmem->minor_faults = pinfo->p_uru_minflt;
    procmem->major_faults = pinfo->p_uru_majflt;
    procmem->page_faults  = procmem->minor_faults + procmem->major_faults;
#endif
    return SIGAR_OK;
}

#define tv2msec(tv) \
   (((sigar_uint64_t)tv.tv_sec * SIGAR_MSEC) + (((sigar_uint64_t)tv.tv_usec) / 1000))

#ifdef DARWIN
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
#  ifdef DARWIN_HAS_LIBPROC_H
    if (sigar->libproc) {
        struct proc_taskinfo pti;
        int sz =
            sigar->proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, sizeof(pti));

        if (sz == sizeof(pti)) {
            time->user = SIGAR_NSEC2MSEC(pti.pti_total_user);
            time->sys  = SIGAR_NSEC2MSEC(pti.pti_total_system);
            time->total = time->user + time->sys;
            return SIGAR_OK;
        }
    }
#  endif

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
#endif

int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_time_t *proctime)
{
#ifdef SIGAR_FREEBSD4
    struct user user;
#endif
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

#if defined(DARWIN)
    if ((status = get_proc_times(sigar, pid, proctime)) != SIGAR_OK) {
        return status;
    }
    proctime->start_time = tv2msec(pinfo->KI_START);
#elif defined(SIGAR_FREEBSD5)
    proctime->user  = tv2msec(pinfo->ki_rusage.ru_utime);
    proctime->sys   = tv2msec(pinfo->ki_rusage.ru_stime);
    proctime->total = proctime->user + proctime->sys;
    proctime->start_time = tv2msec(pinfo->KI_START);
#elif defined(SIGAR_FREEBSD4)
    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    status = kread(sigar, &user, sizeof(user),
                   (u_long)pinfo->kp_proc.p_addr);
    if (status != SIGAR_OK) {
        return status;
    }

    proctime->user  = tv2msec(user.u_stats.p_ru.ru_utime);
    proctime->sys   = tv2msec(user.u_stats.p_ru.ru_stime);
    proctime->total = proctime->user + proctime->sys;
    proctime->start_time = tv2msec(user.u_stats.p_start);
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    /* XXX *_usec */
    proctime->user  = pinfo->p_uutime_sec * SIGAR_MSEC;
    proctime->sys   = pinfo->p_ustime_sec * SIGAR_MSEC;
    proctime->total = proctime->user + proctime->sys;
    proctime->start_time = pinfo->p_ustart_sec * SIGAR_MSEC;
#endif

    return SIGAR_OK;
}

#ifdef DARWIN
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
#endif

int sigar_proc_state_get(sigar_t *sigar, sigar_pid_t pid,
                         sigar_proc_state_t *procstate)
{
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;
#if defined(__OpenBSD__) || defined(__NetBSD__)
    int state = pinfo->p_stat;
#else
    int state = pinfo->KI_STAT;
#endif

    if (status != SIGAR_OK) {
        return status;
    }

#if defined(__OpenBSD__) || defined(__NetBSD__)
    SIGAR_SSTRCPY(procstate->name, pinfo->p_comm);
    procstate->ppid     = pinfo->p_ppid;
    procstate->priority = pinfo->p_priority;
    procstate->nice     = pinfo->p_nice;
    procstate->tty      = pinfo->p_tdev;
    procstate->threads  = SIGAR_FIELD_NOTIMPL;
    procstate->processor = pinfo->p_cpuid;
#else
    SIGAR_SSTRCPY(procstate->name, pinfo->KI_COMM);
    procstate->ppid     = pinfo->KI_PPID;
    procstate->priority = pinfo->KI_PRI;
    procstate->nice     = pinfo->KI_NICE;
    procstate->tty      = SIGAR_FIELD_NOTIMPL; /*XXX*/
    procstate->threads  = SIGAR_FIELD_NOTIMPL;
    procstate->processor = SIGAR_FIELD_NOTIMPL;
#endif

#ifdef DARWIN
    status = sigar_proc_threads_get(sigar, pid, procstate);
    if (status == SIGAR_OK) {
        return status;
    }
#endif

    switch (state) {
      case SIDL:
        procstate->state = 'D';
        break;
      case SRUN:
#ifdef SONPROC
      case SONPROC:
#endif
        procstate->state = 'R';
        break;
      case SSLEEP:
        procstate->state = 'S';
        break;
      case SSTOP:
        procstate->state = 'T';
        break;
      case SZOMB:
        procstate->state = 'Z';
        break;
      default:
        procstate->state = '?';
        break;
    }

    return SIGAR_OK;
}

#define SIGAR_MICROSEC2NANO(s) \
    ((sigar_uint64_t)(s) * (sigar_uint64_t)1000)

#define TIME_NSEC(t) \
    (SIGAR_SEC2NANO((t).tv_sec) + SIGAR_MICROSEC2NANO((t).tv_usec))


int sigar_os_fs_type_get(sigar_file_system_t *fsp)
{
    char *type = fsp->sys_type_name;

    /* see sys/disklabel.h */
    switch (*type) {
      case 'f':
        if (strEQ(type, "ffs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
      case 'h':
        if (strEQ(type, "hfs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
      case 'u':
        if (strEQ(type, "ufs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
    }

    return fsp->type;
}

static void get_fs_options(char *opts, int osize, long flags)
{
    *opts = '\0';
    if (flags & MNT_RDONLY)         strncat(opts, "ro", osize);
    else                            strncat(opts, "rw", osize);
    if (flags & MNT_SYNCHRONOUS)    strncat(opts, ",sync", osize);
    if (flags & MNT_NOEXEC)         strncat(opts, ",noexec", osize);
    if (flags & MNT_NOSUID)         strncat(opts, ",nosuid", osize);
#ifdef MNT_NODEV
    if (flags & MNT_NODEV)          strncat(opts, ",nodev", osize);
#endif
#ifdef MNT_UNION
    if (flags & MNT_UNION)          strncat(opts, ",union", osize);
#endif
    if (flags & MNT_ASYNC)          strncat(opts, ",async", osize);
#ifdef MNT_NOATIME
    if (flags & MNT_NOATIME)        strncat(opts, ",noatime", osize);
#endif
#ifdef MNT_NOCLUSTERR
    if (flags & MNT_NOCLUSTERR)     strncat(opts, ",noclusterr", osize);
#endif
#ifdef MNT_NOCLUSTERW
    if (flags & MNT_NOCLUSTERW)     strncat(opts, ",noclusterw", osize);
#endif
#ifdef MNT_NOSYMFOLLOW
    if (flags & MNT_NOSYMFOLLOW)    strncat(opts, ",nosymfollow", osize);
#endif
#ifdef MNT_SUIDDIR
    if (flags & MNT_SUIDDIR)        strncat(opts, ",suiddir", osize);
#endif
#ifdef MNT_SOFTDEP
    if (flags & MNT_SOFTDEP)        strncat(opts, ",soft-updates", osize);
#endif
    if (flags & MNT_LOCAL)          strncat(opts, ",local", osize);
    if (flags & MNT_QUOTA)          strncat(opts, ",quota", osize);
    if (flags & MNT_ROOTFS)         strncat(opts, ",rootfs", osize);
#ifdef MNT_USER
    if (flags & MNT_USER)           strncat(opts, ",user", osize);
#endif
#ifdef MNT_IGNORE
    if (flags & MNT_IGNORE)         strncat(opts, ",ignore", osize);
#endif
    if (flags & MNT_EXPORTED)       strncat(opts, ",nfs", osize);
}

#ifdef __NetBSD__
#define sigar_statfs statvfs
#define sigar_getfsstat getvfsstat
#define sigar_f_flags f_flag
#else
#define sigar_statfs statfs
#define sigar_getfsstat getfsstat
#define sigar_f_flags f_flags
#endif

int sigar_file_system_list_get(sigar_t *sigar,
                               sigar_file_system_list_t *fslist)
{
    struct sigar_statfs *fs;
    int num, i;
    int is_debug = SIGAR_LOG_IS_DEBUG(sigar);
    long len;

    if ((num = sigar_getfsstat(NULL, 0, MNT_NOWAIT)) < 0) {
        return errno;
    }

    len = sizeof(*fs) * num;
    fs = malloc(len);

    if ((num = sigar_getfsstat(fs, len, MNT_NOWAIT)) < 0) {
        free(fs);
        return errno;
    }

    sigar_file_system_list_create(fslist);

    for (i=0; i<num; i++) {
        sigar_file_system_t *fsp;

#ifdef MNT_AUTOMOUNTED
        if (fs[i].sigar_f_flags & MNT_AUTOMOUNTED) {
            if (is_debug) {
                sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                                 "[file_system_list] skipping automounted %s: %s",
                                 fs[i].f_fstypename, fs[i].f_mntonname);
            }
            continue;
        }
#endif

#ifdef MNT_RDONLY
        if (fs[i].sigar_f_flags & MNT_RDONLY) {
            /* e.g. ftp mount or .dmg image */
            if (is_debug) {
                sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                                 "[file_system_list] skipping readonly %s: %s",
                                 fs[i].f_fstypename, fs[i].f_mntonname);
            }
            continue;
        }
#endif

        SIGAR_FILE_SYSTEM_LIST_GROW(fslist);

        fsp = &fslist->data[fslist->number++];

        SIGAR_SSTRCPY(fsp->dir_name, fs[i].f_mntonname);
        SIGAR_SSTRCPY(fsp->dev_name, fs[i].f_mntfromname);
        SIGAR_SSTRCPY(fsp->sys_type_name, fs[i].f_fstypename);
        get_fs_options(fsp->options, sizeof(fsp->options)-1, fs[i].sigar_f_flags);

        sigar_fs_type_init(fsp);
    }

    free(fs);
    return SIGAR_OK;
}

#ifdef DARWIN
#define IoStatGetValue(key, val) \
    if ((number = (CFNumberRef)CFDictionaryGetValue(stats, CFSTR(kIOBlockStorageDriverStatistics##key)))) \
        CFNumberGetValue(number, kCFNumberSInt64Type, &val)
#endif


#ifdef DARWIN
#define CTL_HW_FREQ_MAX "hw.cpufrequency_max"
#define CTL_HW_FREQ_MIN "hw.cpufrequency_min"
#else
/* XXX FreeBSD 5.x+ only? */
#define CTL_HW_FREQ "machdep.tsc_freq"
#endif


#define rt_s_addr(sa) ((struct sockaddr_in *)(sa))->sin_addr.s_addr

#ifndef SA_SIZE
#define SA_SIZE(sa)                                             \
    (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?      \
        sizeof(long)            :                               \
        1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#endif

typedef enum {
    IFMSG_ITER_LIST,
    IFMSG_ITER_GET
} ifmsg_iter_e;

typedef struct {
    const char *name;
    ifmsg_iter_e type;
    union {
        sigar_net_interface_list_t *iflist;
        struct if_msghdr *ifm;
    } data;
} ifmsg_iter_t;

static int sigar_ifmsg_init(sigar_t *sigar)
{
    int mib[] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_IFLIST, 0 };
    size_t len;

    if (sysctl(mib, NMIB(mib), NULL, &len, NULL, 0) < 0) {
        return errno;
    }

    if (sigar->ifconf_len < len) {
        sigar->ifconf_buf = realloc(sigar->ifconf_buf, len);
        sigar->ifconf_len = len;
    }

    if (sysctl(mib, NMIB(mib), sigar->ifconf_buf, &len, NULL, 0) < 0) {
        return errno;
    }

    return SIGAR_OK;
}

/**
 * @param name name of the interface
 * @param name_len length of name (w/o \0)
 */
static int has_ifaddr(char *name, size_t name_len)
{
    int sock, status;
    struct ifreq ifr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return errno;
    }
    strncpy(ifr.ifr_name, name, MIN(sizeof(ifr.ifr_name) - 1, name_len));
    ifr.ifr_name[MIN(sizeof(ifr.ifr_name) - 1, name_len)] = '\0';
    if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
        status = SIGAR_OK;
    }
    else {
        status = errno;
    }

    close(sock);
    return status;
}

static int sigar_ifmsg_iter(sigar_t *sigar, ifmsg_iter_t *iter)
{
    char *end = sigar->ifconf_buf + sigar->ifconf_len;
    char *ptr = sigar->ifconf_buf;

    if (iter->type == IFMSG_ITER_LIST) {
        sigar_net_interface_list_create(iter->data.iflist);
    }

    while (ptr < end) {
        char *name;
        struct sockaddr_dl *sdl;
        struct if_msghdr *ifm = (struct if_msghdr *)ptr;

        if (ifm->ifm_type != RTM_IFINFO) {
            break;
        }

        ptr += ifm->ifm_msglen;

        while (ptr < end) {
            struct if_msghdr *next = (struct if_msghdr *)ptr;

            if (next->ifm_type != RTM_NEWADDR) {
                break;
            }

            ptr += next->ifm_msglen;
        }

        sdl = (struct sockaddr_dl *)(ifm + 1);
        if (sdl->sdl_family != AF_LINK) {
            continue;
        }

        switch (iter->type) {
          case IFMSG_ITER_LIST:
            if (sdl->sdl_type == IFT_OTHER) {
                if (has_ifaddr(sdl->sdl_data, sdl->sdl_nlen) != SIGAR_OK) {
                    break;
                }
            }
            else if (!((sdl->sdl_type == IFT_ETHER) ||
                       (sdl->sdl_type == IFT_LOOP)))
            {
                break; /* XXX deal w/ other weirdo interfaces */
            }

            SIGAR_NET_IFLIST_GROW(iter->data.iflist);

            /* sdl_data doesn't include a trailing \0, it is only sdl_nlen long */
            name = malloc(sdl->sdl_nlen+1);
            memcpy(name, sdl->sdl_data, sdl->sdl_nlen);
            name[sdl->sdl_nlen] = '\0'; /* add the missing \0 */

            iter->data.iflist->data[iter->data.iflist->number++] = name;
            break;

          case IFMSG_ITER_GET:
            if (strlen(iter->name) == sdl->sdl_nlen && 0 == memcmp(iter->name, sdl->sdl_data, sdl->sdl_nlen)) {
                iter->data.ifm = ifm;
                return SIGAR_OK;
            }
        }
    }

    switch (iter->type) {
      case IFMSG_ITER_LIST:
        return SIGAR_OK;

      case IFMSG_ITER_GET:
      default:
        return ENXIO;
    }
}

int sigar_net_interface_list_get(sigar_t *sigar,
                                 sigar_net_interface_list_t *iflist)
{
    int status;
    ifmsg_iter_t iter;

    if ((status = sigar_ifmsg_init(sigar)) != SIGAR_OK) {
        return status;
    }

    iter.type = IFMSG_ITER_LIST;
    iter.data.iflist = iflist;

    return sigar_ifmsg_iter(sigar, &iter);
}

#include <ifaddrs.h>

/* in6_prefixlen derived from freebsd/sbin/ifconfig/af_inet6.c */
static int sigar_in6_prefixlen(struct sockaddr *netmask)
{
    struct in6_addr *addr = SIGAR_SIN6_ADDR(netmask);
    u_char *name = (u_char *)addr;
    int size = sizeof(*addr);
    int byte, bit, plen = 0;

    for (byte = 0; byte < size; byte++, plen += 8) {
        if (name[byte] != 0xff) {
            break;
        }
    }
    if (byte == size) {
        return plen;
    }
    for (bit = 7; bit != 0; bit--, plen++) {
        if (!(name[byte] & (1 << bit))) {
            break;
        }
    }
    for (; bit != 0; bit--) {
        if (name[byte] & (1 << bit)) {
            return 0;
        }
    }
    byte++;
    for (; byte < size; byte++) {
        if (name[byte]) {
            return 0;
        }
    }
    return plen;
}

int sigar_net_interface_ipv6_config_get(sigar_t *sigar, const char *name,
                                        sigar_net_interface_config_t *ifconfig)
{
    int status = SIGAR_ENOENT;
    struct ifaddrs *addrs, *ifa;

    if (getifaddrs(&addrs) != 0) {
        return errno;
    }

    for (ifa=addrs; ifa; ifa=ifa->ifa_next) {
        if (ifa->ifa_addr &&
            (ifa->ifa_addr->sa_family == AF_INET6) &&
            strEQ(ifa->ifa_name, name))
        {
            status = SIGAR_OK;
            break;
        }
    }

    if (status == SIGAR_OK) {
        struct in6_addr *addr = SIGAR_SIN6_ADDR(ifa->ifa_addr);

        sigar_net_address6_set(ifconfig->address6, addr);
        sigar_net_interface_scope6_set(ifconfig, addr);
        ifconfig->prefix6_length = sigar_in6_prefixlen(ifa->ifa_netmask);
    }

    freeifaddrs(addrs);

    return status;
}

int sigar_net_interface_config_get(sigar_t *sigar, const char *name,
                                   sigar_net_interface_config_t *ifconfig)
{
    int sock;
    int status;
    ifmsg_iter_t iter;
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;
    struct ifreq ifr;

    if (!name) {
        return sigar_net_interface_config_primary_get(sigar, ifconfig);
    }

    if (sigar->ifconf_len == 0) {
        if ((status = sigar_ifmsg_init(sigar)) != SIGAR_OK) {
            return status;
        }
    }

    SIGAR_ZERO(ifconfig);

    iter.type = IFMSG_ITER_GET;
    iter.name = name;

    if ((status = sigar_ifmsg_iter(sigar, &iter)) != SIGAR_OK) {
        return status;
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return errno;
    }

    ifm = iter.data.ifm;

    SIGAR_SSTRCPY(ifconfig->name, name);

    sdl = (struct sockaddr_dl *)(ifm + 1);

    sigar_net_address_mac_set(ifconfig->hwaddr,
                              LLADDR(sdl),
                              sdl->sdl_alen);

    ifconfig->flags = ifm->ifm_flags;
    ifconfig->mtu = ifm->ifm_data.ifi_mtu;
    ifconfig->metric = ifm->ifm_data.ifi_metric;

    SIGAR_SSTRCPY(ifr.ifr_name, name);

#define ifr_s_addr(ifr) \
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr

    if (!ioctl(sock, SIOCGIFADDR, &ifr)) {
        sigar_net_address_set(ifconfig->address,
                              ifr_s_addr(ifr));
    }

    if (!ioctl(sock, SIOCGIFNETMASK, &ifr)) {
        sigar_net_address_set(ifconfig->netmask,
                              ifr_s_addr(ifr));
    }

    if (ifconfig->flags & IFF_LOOPBACK) {
        sigar_net_address_set(ifconfig->destination,
                              ifconfig->address.addr.in);
        sigar_net_address_set(ifconfig->broadcast, 0);
        SIGAR_SSTRCPY(ifconfig->type,
                      SIGAR_NIC_LOOPBACK);
    }
    else {
        if (!ioctl(sock, SIOCGIFDSTADDR, &ifr)) {
            sigar_net_address_set(ifconfig->destination,
                                  ifr_s_addr(ifr));
        }

        if (!ioctl(sock, SIOCGIFBRDADDR, &ifr)) {
            sigar_net_address_set(ifconfig->broadcast,
                                  ifr_s_addr(ifr));
        }
        SIGAR_SSTRCPY(ifconfig->type,
                      SIGAR_NIC_ETHERNET);
    }

    close(sock);

    /* XXX can we get a better description like win32? */
    SIGAR_SSTRCPY(ifconfig->description,
                  ifconfig->name);

    sigar_net_interface_ipv6_config_init(ifconfig);
    sigar_net_interface_ipv6_config_get(sigar, name, ifconfig);

    return SIGAR_OK;
}


static int net_connection_state_get(int state)
{
    switch (state) {
      case TCPS_CLOSED:
        return SIGAR_TCP_CLOSE;
      case TCPS_LISTEN:
        return SIGAR_TCP_LISTEN;
      case TCPS_SYN_SENT:
        return SIGAR_TCP_SYN_SENT;
      case TCPS_SYN_RECEIVED:
        return SIGAR_TCP_SYN_RECV;
      case TCPS_ESTABLISHED:
        return SIGAR_TCP_ESTABLISHED;
      case TCPS_CLOSE_WAIT:
        return SIGAR_TCP_CLOSE_WAIT;
      case TCPS_FIN_WAIT_1:
        return SIGAR_TCP_FIN_WAIT1;
      case TCPS_CLOSING:
        return SIGAR_TCP_CLOSING;
      case TCPS_LAST_ACK:
        return SIGAR_TCP_LAST_ACK;
      case TCPS_FIN_WAIT_2:
        return SIGAR_TCP_FIN_WAIT2;
      case TCPS_TIME_WAIT:
        return SIGAR_TCP_TIME_WAIT;
      default:
        return SIGAR_TCP_UNKNOWN;
    }
}

#if defined(__OpenBSD__) || defined(__NetBSD__)
static int net_connection_get(sigar_net_connection_walker_t *walker, int proto)
{
    int status;
    int istcp = 0, type;
    int flags = walker->flags;
    struct inpcbtable table;
    struct inpcb *head, *next, *prev;
    sigar_t *sigar = walker->sigar;
    u_long offset;

    switch (proto) {
      case IPPROTO_TCP:
        offset = sigar->koffsets[KOFFSET_TCBTABLE];
        istcp = 1;
        type = SIGAR_NETCONN_TCP;
        break;
      case IPPROTO_UDP:
      default:
        return SIGAR_ENOTIMPL;
    }


    status = kread(sigar, &table, sizeof(table), offset);

    if (status != SIGAR_OK) {
        return status;
    }

    prev = head =
        (struct inpcb *)&CIRCLEQ_FIRST(&((struct inpcbtable *)offset)->inpt_queue);

    next = (struct inpcb *)CIRCLEQ_FIRST(&table.inpt_queue);

    while (next != head) {
        struct inpcb inpcb;
        struct tcpcb tcpcb;
        struct socket socket;

        status = kread(sigar, &inpcb, sizeof(inpcb), (long)next);
        prev = next;
        next = (struct inpcb *)CIRCLEQ_NEXT(&inpcb, inp_queue);

        kread(sigar, &socket, sizeof(socket), (u_long)inpcb.inp_socket);

        if ((((flags & SIGAR_NETCONN_SERVER) && socket.so_qlimit) ||
            ((flags & SIGAR_NETCONN_CLIENT) && !socket.so_qlimit)))
        {
            sigar_net_connection_t conn;

            SIGAR_ZERO(&conn);

            if (istcp) {
                kread(sigar, &tcpcb, sizeof(tcpcb), (u_long)inpcb.inp_ppcb);
            }

#ifdef __NetBSD__
            if (inpcb.inp_af == AF_INET6) {
                /*XXX*/
                continue;
            }
#else
            if (inpcb.inp_flags & INP_IPV6) {
                sigar_net_address6_set(conn.local_address,
                                       &inpcb.inp_laddr6.s6_addr);

                sigar_net_address6_set(conn.remote_address,
                                       &inpcb.inp_faddr6.s6_addr);
            }
#endif
            else {
                sigar_net_address_set(conn.local_address,
                                      inpcb.inp_laddr.s_addr);

                sigar_net_address_set(conn.remote_address,
                                      inpcb.inp_faddr.s_addr);
            }

            conn.local_port  = ntohs(inpcb.inp_lport);
            conn.remote_port = ntohs(inpcb.inp_fport);
            conn.receive_queue = socket.so_rcv.sb_cc;
            conn.send_queue    = socket.so_snd.sb_cc;
            conn.uid           = socket.so_pgid;
            conn.type = type;

            if (!istcp) {
                conn.state = SIGAR_TCP_UNKNOWN;
                if (walker->add_connection(walker, &conn) != SIGAR_OK) {
                    break;
                }
                continue;
            }

            conn.state = net_connection_state_get(tcpcb.t_state);

            if (walker->add_connection(walker, &conn) != SIGAR_OK) {
                break;
            }
        }
    }

    return SIGAR_OK;
}
#else
static int net_connection_get(sigar_net_connection_walker_t *walker, int proto)
{
    int flags = walker->flags;
    int type, istcp = 0;
    char *buf;
    const char *mibvar;
    struct tcpcb *tp = NULL;
    struct inpcb *inp;
    struct xinpgen *xig, *oxig;
    struct xsocket *so;
    size_t len;

    switch (proto) {
      case IPPROTO_TCP:
        mibvar = "net.inet.tcp.pcblist";
        istcp = 1;
        type = SIGAR_NETCONN_TCP;
        break;
      case IPPROTO_UDP:
        mibvar = "net.inet.udp.pcblist";
        type = SIGAR_NETCONN_UDP;
        break;
      default:
        mibvar = "net.inet.raw.pcblist";
        type = SIGAR_NETCONN_RAW;
        break;
    }

    len = 0;
    if (sysctlbyname(mibvar, 0, &len, 0, 0) < 0) {
        return errno;
    }
    if ((buf = malloc(len)) == 0) {
        return errno;
    }
    if (sysctlbyname(mibvar, buf, &len, 0, 0) < 0) {
        free(buf);
        return errno;
    }

    oxig = xig = (struct xinpgen *)buf;
    for (xig = (struct xinpgen *)((char *)xig + xig->xig_len);
         xig->xig_len > sizeof(struct xinpgen);
         xig = (struct xinpgen *)((char *)xig + xig->xig_len))
    {
        if (istcp) {
            struct xtcpcb *cb = (struct xtcpcb *)xig;
            tp = &cb->xt_tp;
            inp = &cb->xt_inp;
            so = &cb->xt_socket;
        }
        else {
            struct xinpcb *cb = (struct xinpcb *)xig;
            inp = &cb->xi_inp;
            so = &cb->xi_socket;
        }

        if (so->xso_protocol != proto) {
            continue;
        }

        if (inp->inp_gencnt > oxig->xig_gen) {
            continue;
        }

        if ((((flags & SIGAR_NETCONN_SERVER) && so->so_qlimit) ||
            ((flags & SIGAR_NETCONN_CLIENT) && !so->so_qlimit)))
        {
            sigar_net_connection_t conn;

            SIGAR_ZERO(&conn);

            if (inp->inp_vflag & INP_IPV6) {
                sigar_net_address6_set(conn.local_address,
                                       &inp->in6p_laddr.s6_addr);

                sigar_net_address6_set(conn.remote_address,
                                       &inp->in6p_faddr.s6_addr);
            }
            else {
                sigar_net_address_set(conn.local_address,
                                      inp->inp_laddr.s_addr);

                sigar_net_address_set(conn.remote_address,
                                      inp->inp_faddr.s_addr);
            }

            conn.local_port  = ntohs(inp->inp_lport);
            conn.remote_port = ntohs(inp->inp_fport);
            conn.receive_queue = so->so_rcv.sb_cc;
            conn.send_queue    = so->so_snd.sb_cc;
            conn.uid           = so->so_pgid;
            conn.type = type;

            if (!istcp) {
                conn.state = SIGAR_TCP_UNKNOWN;
                if (walker->add_connection(walker, &conn) != SIGAR_OK) {
                    break;
                }
                continue;
            }

            conn.state = net_connection_state_get(tp->t_state);

            if (walker->add_connection(walker, &conn) != SIGAR_OK) {
                break;
            }
        }
    }

    free(buf);

    return SIGAR_OK;
}
#endif

int sigar_net_connection_walk(sigar_net_connection_walker_t *walker)
{
    int flags = walker->flags;
    int status;

    if (flags & SIGAR_NETCONN_TCP) {
        status = net_connection_get(walker, IPPROTO_TCP);
        if (status != SIGAR_OK) {
            return status;
        }
    }
    if (flags & SIGAR_NETCONN_UDP) {
        status = net_connection_get(walker, IPPROTO_UDP);
        if (status != SIGAR_OK) {
            return status;
        }
    }

    return SIGAR_OK;
}
