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

#define SIGAR_PROC_STATE_SLEEP  'S'
#define SIGAR_PROC_STATE_RUN    'R'
#define SIGAR_PROC_STATE_STOP   'T'
#define SIGAR_PROC_STATE_ZOMBIE 'Z'
#define SIGAR_PROC_STATE_IDLE   'D'

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
    size_t len;
    struct timeval boottime;
#ifndef DARWIN
    struct stat sb;
#endif

    len = sizeof(boottime);
    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;
    if (sysctl(mib, NMIB(mib), &boottime, &len, NULL, 0) < 0) {
        return errno;
    }

    *sigar = malloc(sizeof(**sigar));
    if (*sigar == NULL) {
        return SIGAR_ENOMEM;
    }

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

    swap->allocstall = -1;
    swap->allocstall_dma = -1;
    swap->allocstall_dma32 = -1;
    swap->allocstall_normal = -1;
    swap->allocstall_movable = -1;

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
