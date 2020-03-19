/*
 * Copyright (c) 2004-2008 Hyperic, Inc.
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

#include <inet/ip.h>
#include <inet/tcp.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/lwp.h>
#include <sys/proc.h>
#include <sys/sockio.h>
#include <sys/swap.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <dlfcn.h>
#include <dirent.h>

#define PROC_ERRNO ((errno == ENOENT) ? ESRCH : errno)
#define SIGAR_USR_UCB_PS "/usr/ucb/ps"


/* like kstat_lookup but start w/ ksp->ks_next instead of kc->kc_chain */
static kstat_t *
kstat_next(kstat_t *ksp, char *ks_module, int ks_instance, char *ks_name)
{
    if (ksp) {
        ksp = ksp->ks_next;
    }
    for (; ksp; ksp = ksp->ks_next) {
        if ((ks_module == NULL ||
             strcmp(ksp->ks_module, ks_module) == 0) &&
            (ks_instance == -1 || ksp->ks_instance == ks_instance) &&
            (ks_name == NULL || strcmp(ksp->ks_name, ks_name) == 0))
            return ksp;
    }

    errno = ENOENT;
    return NULL;
}

int sigar_os_open(sigar_t **sig)
{
    kstat_ctl_t *kc;
    kstat_t *ksp;
    sigar_t *sigar;
    int i, status;
    struct utsname name;
    char *ptr;

    if ((kc = kstat_open()) == NULL) {
       *sig = NULL;
       return errno;
    }

    /*
     * Use calloc instead of malloc to set everything to 0
     * to avoid having to set each individual member to 0/NULL
     * later.
     */
    if ((*sig = sigar = calloc(1, sizeof(*sigar))) == NULL) {
       return ENOMEM;
    }

    uname(&name);
    if ((ptr = strchr(name.release, '.'))) {
        sigar->solaris_version = atoi(ptr + 1);
    }
    else {
        sigar->solaris_version = 6;
    }

    if ((ptr = getenv("SIGAR_USE_UCB_PS"))) {
        sigar->use_ucb_ps = strEQ(ptr, "true");
    }

    if (sigar->use_ucb_ps) {
        if (access(SIGAR_USR_UCB_PS, X_OK) == -1) {
            sigar->use_ucb_ps = 0;
        }
        else {
            sigar->use_ucb_ps = 1;
        }
    }

    sigar->pagesize = 0;
    i = sysconf(_SC_PAGESIZE);
    while ((i >>= 1) > 0) {
        sigar->pagesize++;
    }

    sigar->ticks = sysconf(_SC_CLK_TCK);
    sigar->kc = kc;

    sigar->koffsets.system[0] = -1;
    sigar->koffsets.mempages[0] = -1;
    sigar->koffsets.syspages[0] = -1;

    if ((status = sigar_get_kstats(sigar)) != SIGAR_OK) {
        fprintf(stderr, "status=%d\n", status);
    }

    if ((ksp = sigar->ks.system) &&
        (kstat_read(kc, ksp, NULL) >= 0))
    {
        sigar_koffsets_init_system(sigar, ksp);

        sigar->boot_time = kSYSTEM(KSTAT_SYSTEM_BOOT_TIME);
    }

    sigar->last_pid = -1;
    sigar->mib2.sd = -1;

    return SIGAR_OK;
}

static int sigar_cpu_list_destroy(sigar_t *sigar, sigar_cpu_list_t *cpulist)
{
    if (cpulist->size) {
        free(cpulist->data);
        cpulist->number = cpulist->size = 0;
    }

    return SIGAR_OK;
}

int sigar_os_close(sigar_t *sigar)
{
    kstat_close(sigar->kc);
    if (sigar->mib2.sd != -1) {
        close_mib2(&sigar->mib2);
    }

    if (sigar->ks.lcpu) {
        free(sigar->ks.cpu);
        free(sigar->ks.cpu_info);
        free(sigar->ks.cpuid);
    }
    if (sigar->pinfo) {
        free(sigar->pinfo);
    }
    if (sigar->cpulist.size != 0) {
        sigar_cpu_list_destroy(sigar, &sigar->cpulist);
    }
    if (sigar->plib) {
        dlclose(sigar->plib);
    }
    if (sigar->pargs) {
        sigar_cache_destroy(sigar->pargs);
    }
    free(sigar);
    return SIGAR_OK;
}

char *sigar_os_error_string(sigar_t *sigar, int err)
{
    switch (err) {
      case SIGAR_EMIB2:
        return sigar->mib2.errmsg;
      default:
        return NULL;
    }
}

int sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem)
{
    kstat_ctl_t *kc = sigar->kc;
    kstat_t *ksp;
    sigar_uint64_t kern = 0;

    SIGAR_ZERO(mem);

    /* XXX: is mem hot swappable or can we just do this during open ? */
    mem->total = sysconf(_SC_PHYS_PAGES);
    mem->total <<= sigar->pagesize;

    if (sigar_kstat_update(sigar) == -1) {
        return errno;
    }

    if ((ksp = sigar->ks.syspages) && kstat_read(kc, ksp, NULL) >= 0) {
        sigar_koffsets_init_syspages(sigar, ksp);

        mem->free = kSYSPAGES(KSTAT_SYSPAGES_FREE);
        mem->free <<= sigar->pagesize;

        mem->used = mem->total - mem->free;
    }

    if ((ksp = sigar->ks.mempages) && kstat_read(kc, ksp, NULL) >= 0) {
        sigar_koffsets_init_mempages(sigar, ksp);
    }

    /* XXX mdb ::memstat cachelist/freelist not available to kstat, see: */
    /* http://bugs.opensolaris.org/bugdatabase/view_bug.do?bug_id=6821980 */

    /* ZFS ARC cache. see: http://opensolaris.org/jive/thread.jspa?messageID=393695 */
    if ((ksp = kstat_lookup(sigar->kc, "zfs", 0, "arcstats")) &&
        (kstat_read(sigar->kc, ksp, NULL) != -1))
    {
        kstat_named_t *kn;

        if ((kn = (kstat_named_t *)kstat_data_lookup(ksp, "size"))) {
            kern = kn->value.i64;
        }
        if ((kn = (kstat_named_t *)kstat_data_lookup(ksp, "c_min"))) {
            /* c_min cannot be reclaimed they say */
            if (kern > kn->value.i64) {
                kern -= kn->value.i64;
            }
        }
    }

    mem->actual_free = mem->free + kern;
    mem->actual_used = mem->used - kern;

    sigar_mem_calc_ram(sigar, mem);

    return SIGAR_OK;
}

int sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap)
{
    kstat_t *ksp;
    kstat_named_t *kn;
    swaptbl_t *stab;
    int num, i;
    char path[PATH_MAX+1]; /* {un,re}used */

    /* see: man swapctl(2) */
    if ((num = swapctl(SC_GETNSWP, NULL)) == -1) {
        return errno;
    }

    stab = malloc(num * sizeof(stab->swt_ent[0]) + sizeof(*stab));

    stab->swt_n = num;
    for (i=0; i<num; i++) {
        stab->swt_ent[i].ste_path = path;
    }

    if ((num = swapctl(SC_LIST, stab)) == -1) {
        free(stab);
        return errno;
    }

    num = num < stab->swt_n ? num : stab->swt_n;
    swap->total = swap->free = 0;
    for (i=0; i<num; i++) {
        if (stab->swt_ent[i].ste_flags & ST_INDEL) {
            continue; /* swap file is being deleted */
        }
        swap->total += stab->swt_ent[i].ste_pages;
        swap->free  += stab->swt_ent[i].ste_free;
    }
    free(stab);

    swap->total <<= sigar->pagesize;
    swap->free  <<= sigar->pagesize;
    swap->used  = swap->total - swap->free;

    swap->allocstall = -1;
    swap->allocstall_dma = -1;
    swap->allocstall_dma32 = -1;
    swap->allocstall_normal = -1;
    swap->allocstall_movable = -1;

    if (sigar_kstat_update(sigar) == -1) {
        return errno;
    }
    if (!(ksp = kstat_lookup(sigar->kc, "cpu", -1, "vm"))) {
        swap->page_in = swap->page_out = SIGAR_FIELD_NOTIMPL;
        return SIGAR_OK;
    }

    swap->page_in = swap->page_out = 0;

    /* XXX: these stats do not exist in this form on solaris 8 or 9.
     * they are in the raw cpu_stat struct, but thats not
     * binary compatible
     */
    do {
        if (kstat_read(sigar->kc, ksp, NULL) < 0) {
            break;
        }

        if ((kn = (kstat_named_t *)kstat_data_lookup(ksp, "pgin"))) {
            swap->page_in += kn->value.i64;  /* vmstat -s | grep "page ins" */
        }
        if ((kn = (kstat_named_t *)kstat_data_lookup(ksp, "pgout"))) {
            swap->page_out += kn->value.i64; /* vmstat -s | grep "page outs" */
        }
    } while ((ksp = kstat_next(ksp, "cpu", -1, "vm")));

    return SIGAR_OK;
}

#ifndef KSTAT_NAMED_STR_PTR
/* same offset as KSTAT_NAMED_STR_PTR(brand) */
#define KSTAT_NAMED_STR_PTR(n) (char *)((n)->value.i32)
#endif


static void free_chip_id(void *ptr)
{
    /*noop*/
}

static int get_chip_id(sigar_t *sigar, int processor)
{
    kstat_t *ksp = sigar->ks.cpu_info[processor];
    kstat_named_t *chipid;

    if (ksp &&
        (kstat_read(sigar->kc, ksp, NULL) != -1) &&
        (chipid = (kstat_named_t *)kstat_data_lookup(ksp, "chip_id")))
    {
        return chipid->value.i32;
    }
    else {
        return -1;
    }
}

static int sigar_cpu_list_get(sigar_t *sigar, sigar_cpu_list_t *cpulist);

int sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    int status, i;

    status = sigar_cpu_list_get(sigar, &sigar->cpulist);

    if (status != SIGAR_OK) {
        return status;
    }

    SIGAR_ZERO(cpu);

    for (i=0; i<sigar->cpulist.number; i++) {
        sigar_cpu_t *xcpu = &sigar->cpulist.data[i];

        cpu->user  += xcpu->user;
        cpu->sys   += xcpu->sys;
        cpu->idle  += xcpu->idle;
        cpu->nice  += xcpu->nice;
        cpu->wait  += xcpu->wait;
        cpu->total += xcpu->total;
    }

    return SIGAR_OK;
}



static int sigar_cpu_list_create(sigar_cpu_list_t *cpulist);

static int sigar_cpu_list_grow(sigar_cpu_list_t *cpulist);

#define SIGAR_CPU_LIST_GROW(cpulist) \
    if (cpulist->number >= cpulist->size) { \
        sigar_cpu_list_grow(cpulist); \
    }

static int sigar_cpu_list_create(sigar_cpu_list_t *cpulist)
{
    cpulist->number = 0;
    cpulist->size = SIGAR_CPU_INFO_MAX;
    cpulist->data = malloc(sizeof(*(cpulist->data)) *
                           cpulist->size);
    return SIGAR_OK;
}

static int sigar_cpu_list_grow(sigar_cpu_list_t *cpulist)
{
    cpulist->data = realloc(cpulist->data,
                            sizeof(*(cpulist->data)) *
                            (cpulist->size + SIGAR_CPU_INFO_MAX));
    cpulist->size += SIGAR_CPU_INFO_MAX;

    return SIGAR_OK;
}




static int sigar_cpu_list_get(sigar_t *sigar, sigar_cpu_list_t *cpulist)
{
    kstat_ctl_t *kc = sigar->kc;
    kstat_t *ksp;
    uint_t cpuinfo[CPU_STATES];
    unsigned int i;
    int is_debug = SIGAR_LOG_IS_DEBUG(sigar);
    sigar_cache_t *chips;

    if (sigar_kstat_update(sigar) == -1) {
        return errno;
    }

    if (cpulist == &sigar->cpulist) {
        if (sigar->cpulist.size == 0) {
            /* create once */
            sigar_cpu_list_create(cpulist);
        }
        else {
            /* reset, re-using cpulist.data */
            sigar->cpulist.number = 0;
        }
    }
    else {
        sigar_cpu_list_create(cpulist);
    }

    if (is_debug) {
        sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                         "[cpu_list] OS reports %d CPUs",
                         sigar->ncpu);
    }

    chips = sigar_cache_new(16);
    chips->free_value = free_chip_id;

    for (i=0; i<sigar->ncpu; i++) {
        sigar_cpu_t *cpu;
        char *buf;
        int chip_id;
        sigar_cache_entry_t *ent;

        if (!CPU_ONLINE(sigar->ks.cpuid[i])) {
            sigar_log_printf(sigar, SIGAR_LOG_INFO,
                             "cpu %d (id=%d) is offline",
                             i, sigar->ks.cpuid[i]);
            continue;
        }

        if (!(ksp = sigar->ks.cpu[i])) {
            sigar_log_printf(sigar, SIGAR_LOG_ERROR,
                             "NULL ksp for cpu %d (id=%d)",
                             i, sigar->ks.cpuid[i]);
            continue; /* shouldnot happen */
        }

        if (kstat_read(kc, ksp, NULL) < 0) {
            sigar_log_printf(sigar, SIGAR_LOG_ERROR,
                             "kstat_read failed for cpu %d (id=%d): %s",
                             i, sigar->ks.cpuid[i],
                             sigar_strerror(sigar, errno));
            continue; /* shouldnot happen */
        }

        /*
         * cpu_stat_t is not binary compatible between solaris versions.
         * since cpu_stat is a 'raw' kstat and not 'named' we cannot
         * use name based lookups as we do for others.
         * the start of the cpu_stat_t structure is binary compatible,
         * which looks like so:
         * typedef struct cpu_stat {
         *    kmutex_t        cpu_stat_lock;
         *    cpu_sysinfo_t   cpu_sysinfo;
         *    ...
         *    typedef struct cpu_sysinfo {
         *       ulong cpu[CPU_STATES];
         *       ...
         * we just copy the piece we need below:
         */
        buf = ksp->ks_data;
        buf += sizeof(kmutex_t);
        memcpy(&cpuinfo[0], buf, sizeof(cpuinfo));
        chip_id = sigar->cpu_list_cores ? -1 : get_chip_id(sigar, i);

        if (chip_id == -1) {
            SIGAR_CPU_LIST_GROW(cpulist);
            cpu = &cpulist->data[cpulist->number++];
            SIGAR_ZERO(cpu);
        }
        else {
            /* merge times of logical processors */
            ent = sigar_cache_get(chips, chip_id);
            if (ent->value) {
                cpu = &cpulist->data[(long)ent->value-1];
            }
            else {
                SIGAR_CPU_LIST_GROW(cpulist);
                cpu = &cpulist->data[cpulist->number++];
                ent->value = (void *)(long)cpulist->number;
                SIGAR_ZERO(cpu);

                if (is_debug) {
                    sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                                     "[cpu_list] Merging times of"
                                     " logical processors for chip_id=%d",
                                     chip_id);
                }
            }
        }

        cpu->user += SIGAR_TICK2MSEC(cpuinfo[CPU_USER]);
        cpu->sys  += SIGAR_TICK2MSEC(cpuinfo[CPU_KERNEL]);
        cpu->idle += SIGAR_TICK2MSEC(cpuinfo[CPU_IDLE]);
        cpu->wait += SIGAR_TICK2MSEC(cpuinfo[CPU_WAIT]);
        cpu->nice += 0; /* no cpu->nice */
        cpu->total = cpu->user + cpu->sys + cpu->idle + cpu->wait;
    }

    sigar_cache_destroy(chips);

    return SIGAR_OK;
}

#define LIBPROC "/usr/lib/libproc.so"

#define CHECK_PSYM(s) \
    if (!sigar->s) { \
        sigar_log_printf(sigar, SIGAR_LOG_WARN, \
                         "[%s] Symbol not found: %s", \
                         SIGAR_FUNC, #s); \
        dlclose(sigar->plib); \
        sigar->plib = NULL; \
        return SIGAR_ENOTIMPL; \
    }


/* from libproc.h, not included w/ solaris distro */
/* Error codes from Pgrab(), Pfgrab_core(), and Pgrab_core() */
#define G_STRANGE       -1      /* Unanticipated error, errno is meaningful */
#define G_NOPROC        1       /* No such process */
#define G_NOCORE        2       /* No such core file */
#define G_NOPROCORCORE  3       /* No such proc or core (for proc_arg_grab) */
#define G_NOEXEC        4       /* Cannot locate executable file */
#define G_ZOMB          5       /* Zombie process */
#define G_PERM          6       /* No permission */
#define G_BUSY          7       /* Another process has control */
#define G_SYS           8       /* System process */
#define G_SELF          9       /* Process is self */
#define G_INTR          10      /* Interrupt received while grabbing */
#define G_LP64          11      /* Process is _LP64, self is ILP32 */
#define G_FORMAT        12      /* File is not an ELF format core file */
#define G_ELF           13      /* Libelf error, elf_errno() is meaningful */
#define G_NOTE          14      /* Required PT_NOTE Phdr not present in core */


int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist)
{
    return sigar_proc_list_procfs_get(sigar, proclist);
}

int sigar_proc_mem_get(sigar_t *sigar, sigar_pid_t pid,
                       sigar_proc_mem_t *procmem)
{
    int status = sigar_proc_psinfo_get(sigar, pid);
    psinfo_t *pinfo = sigar->pinfo;
    prusage_t usage;

    if (status != SIGAR_OK) {
        return status;
    }

    procmem->size     = pinfo->pr_size << 10;
    procmem->resident = pinfo->pr_rssize << 10;
    procmem->share    = SIGAR_FIELD_NOTIMPL;

    if (sigar_proc_usage_get(sigar, &usage, pid) == SIGAR_OK) {
        procmem->minor_faults = usage.pr_minf;
        procmem->major_faults = usage.pr_majf;
        procmem->page_faults =
            procmem->minor_faults +
            procmem->major_faults;
    }
    else {
        procmem->minor_faults = SIGAR_FIELD_NOTIMPL;
        procmem->major_faults = SIGAR_FIELD_NOTIMPL;
        procmem->page_faults = SIGAR_FIELD_NOTIMPL;
    }

    return SIGAR_OK;
}

#define TIMESTRUCT_2MSEC(t) \
    ((t.tv_sec * MILLISEC) + (t.tv_nsec / (NANOSEC/MILLISEC)))

int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_time_t *proctime)
{
    prusage_t usage;
    int status;

    if ((status = sigar_proc_usage_get(sigar, &usage, pid)) != SIGAR_OK) {
        return status;
    }

    proctime->start_time = usage.pr_create.tv_sec + sigar->boot_time;
    proctime->start_time *= MILLISEC;

    if (usage.pr_utime.tv_sec < 0) {
        /* XXX wtf?  seen on solaris 10, only for the self process */
        pstatus_t pstatus;

        status = sigar_proc_status_get(sigar, &pstatus, pid);
        if (status != SIGAR_OK) {
            return status;
        }

        usage.pr_utime.tv_sec  = pstatus.pr_utime.tv_sec;
        usage.pr_utime.tv_nsec = pstatus.pr_utime.tv_nsec;
        usage.pr_stime.tv_sec  = pstatus.pr_stime.tv_sec;
        usage.pr_stime.tv_nsec = pstatus.pr_stime.tv_nsec;
    }

    proctime->user = TIMESTRUCT_2MSEC(usage.pr_utime);
    proctime->sys  = TIMESTRUCT_2MSEC(usage.pr_stime);
    proctime->total = proctime->user + proctime->sys;

    return SIGAR_OK;
}

int sigar_proc_state_get(sigar_t *sigar, sigar_pid_t pid,
                         sigar_proc_state_t *procstate)
{
    int status = sigar_proc_psinfo_get(sigar, pid);
    psinfo_t *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    SIGAR_SSTRCPY(procstate->name, pinfo->pr_fname);
    procstate->ppid = pinfo->pr_ppid;
    procstate->tty  = pinfo->pr_ttydev;
    procstate->priority = pinfo->pr_lwp.pr_pri;
    procstate->nice     = pinfo->pr_lwp.pr_nice - NZERO;
    procstate->threads  = pinfo->pr_nlwp;
    procstate->processor = pinfo->pr_lwp.pr_onpro;

    switch (pinfo->pr_lwp.pr_state) {
      case SONPROC:
      case SRUN:
        procstate->state = 'R';
        break;
      case SZOMB:
        procstate->state = 'Z';
        break;
      case SSLEEP:
        procstate->state = 'S';
        break;
      case SSTOP:
        procstate->state = 'T';
        break;
      case SIDL:
        procstate->state = 'D';
        break;
    }

    return SIGAR_OK;
}

#include <sys/mnttab.h>

int sigar_os_fs_type_get(sigar_file_system_t *fsp)
{
    char *type = fsp->sys_type_name;

    switch (*type) {
      case 'u':
        if (strEQ(type, "ufs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
        /* XXX */
    }

    return fsp->type;
}

int sigar_file_system_list_get(sigar_t *sigar,
                               sigar_file_system_list_t *fslist)
{
    struct mnttab ent;
    sigar_file_system_t *fsp;
    FILE *fp = fopen(MNTTAB, "r");

    if (!fp) {
        return errno;
    }

    sigar_file_system_list_create(fslist);

    while (getmntent(fp, &ent) == 0) {
        if (strstr(ent.mnt_mntopts, "ignore")) {
            continue; /* e.g. vold */
        }

        SIGAR_FILE_SYSTEM_LIST_GROW(fslist);

        fsp = &fslist->data[fslist->number++];

        SIGAR_SSTRCPY(fsp->dir_name, ent.mnt_mountp);
        SIGAR_SSTRCPY(fsp->dev_name, ent.mnt_special);
        SIGAR_SSTRCPY(fsp->sys_type_name, ent.mnt_fstype);
        SIGAR_SSTRCPY(fsp->options, ent.mnt_mntopts);
        sigar_fs_type_init(fsp);
    }

    fclose(fp);

    return SIGAR_OK;
}

int sigar_net_interface_ipv6_config_get(sigar_t *sigar, const char *name,
                                        sigar_net_interface_config_t *ifconfig)
{
    int sock;
    struct lifreq lifr;

    if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        return errno;
    }

    SIGAR_SSTRCPY(lifr.lifr_name, name);

    if (ioctl(sock, SIOCGLIFADDR, &lifr) == 0) {
        struct in6_addr *addr = SIGAR_SIN6_ADDR(&lifr.lifr_addr);

        sigar_net_address6_set(ifconfig->address6, addr);
        sigar_net_interface_scope6_set(ifconfig, addr);
        ifconfig->prefix6_length = lifr.lifr_addrlen;
    }

    close(sock);
    return SIGAR_OK;
}

#define TCPQ_SIZE(s) ((s) >= 0 ? (s) : 0)

static int tcp_connection_get(sigar_net_connection_walker_t *walker,
                              struct mib2_tcpConnEntry *entry,
                              int len)
{
    int flags = walker->flags;
    int status;
    char *end = (char *)entry + len;

    while ((char *)entry < end) {
        int state = entry->tcpConnEntryInfo.ce_state;

        if (((flags & SIGAR_NETCONN_SERVER) && (state == TCPS_LISTEN)) ||
            ((flags & SIGAR_NETCONN_CLIENT) && (state != TCPS_LISTEN)))
        {
            sigar_net_connection_t conn;

            SIGAR_ZERO(&conn);

            sigar_net_address_set(conn.local_address, entry->tcpConnLocalAddress);
            sigar_net_address_set(conn.remote_address, entry->tcpConnRemAddress);

            conn.local_port = entry->tcpConnLocalPort;
            conn.remote_port = entry->tcpConnRemPort;
            conn.type = SIGAR_NETCONN_TCP;
            conn.send_queue =
                TCPQ_SIZE(entry->tcpConnEntryInfo.ce_snxt -
                          entry->tcpConnEntryInfo.ce_suna - 1);
            conn.receive_queue =
                TCPQ_SIZE(entry->tcpConnEntryInfo.ce_rnxt -
                          entry->tcpConnEntryInfo.ce_rack);

            switch (state) {
              case TCPS_CLOSED:
                conn.state = SIGAR_TCP_CLOSE;
                break;
              case TCPS_IDLE:
                conn.state = SIGAR_TCP_IDLE;
                break;
              case TCPS_BOUND:
                conn.state = SIGAR_TCP_BOUND;
                break;
              case TCPS_LISTEN:
                conn.state = SIGAR_TCP_LISTEN;
                break;
              case TCPS_SYN_SENT:
                conn.state = SIGAR_TCP_SYN_SENT;
                break;
              case TCPS_SYN_RCVD:
                conn.state = SIGAR_TCP_SYN_RECV;
                break;
              case TCPS_ESTABLISHED:
                conn.state = SIGAR_TCP_ESTABLISHED;
                break;
              case TCPS_CLOSE_WAIT:
                conn.state = SIGAR_TCP_CLOSE_WAIT;
                break;
              case TCPS_FIN_WAIT_1:
                conn.state = SIGAR_TCP_FIN_WAIT1;
                break;
              case TCPS_CLOSING:
                conn.state = SIGAR_TCP_CLOSING;
                break;
              case TCPS_LAST_ACK:
                conn.state = SIGAR_TCP_LAST_ACK;
                break;
              case TCPS_FIN_WAIT_2:
                conn.state = SIGAR_TCP_FIN_WAIT2;
                break;
              case TCPS_TIME_WAIT:
                conn.state = SIGAR_TCP_TIME_WAIT;
                break;
              default:
                conn.state = SIGAR_TCP_UNKNOWN;
                break;
            }

            status = walker->add_connection(walker, &conn);
            if (status != SIGAR_OK) {
                return status;
            }
        }

        entry++;
    }

    return SIGAR_OK;
}

static int udp_connection_get(sigar_net_connection_walker_t *walker,
                              struct mib2_udpEntry *entry,
                              int len)
{
    int flags = walker->flags;
    int status;
    char *end = (char *)entry + len;

    while ((char *)entry < end) {
        int state = entry->udpEntryInfo.ue_state;

        /* XXX dunno if this state check is right */
        if (((flags & SIGAR_NETCONN_SERVER) && (state == MIB2_UDP_idle)) ||
            ((flags & SIGAR_NETCONN_CLIENT) && (state != MIB2_UDP_idle)))
        {
            sigar_net_connection_t conn;

            SIGAR_ZERO(&conn);

            sigar_net_address_set(conn.local_address, entry->udpLocalAddress);
            sigar_net_address_set(conn.remote_address, 0);

            conn.local_port = entry->udpLocalPort;
            conn.remote_port = 0;
            conn.type = SIGAR_NETCONN_UDP;

            status = walker->add_connection(walker, &conn);
            if (status != SIGAR_OK) {
                return status;
            }
        }

        entry++;
    }

    return SIGAR_OK;
}

int sigar_net_connection_walk(sigar_net_connection_walker_t *walker)
{
    sigar_t *sigar = walker->sigar;
    int flags = walker->flags;
    int status;
    int want_tcp = flags & SIGAR_NETCONN_TCP;
    int want_udp = flags & SIGAR_NETCONN_UDP;
    char *data;
    int len;
    int rc;
    struct opthdr *op;

    while ((rc = get_mib2(&sigar->mib2, &op, &data, &len)) == GET_MIB2_OK) {
        if ((op->level == MIB2_TCP) &&
            (op->name == MIB2_TCP_13) &&
            want_tcp)
        {
            status =
                tcp_connection_get(walker,
                                   (struct mib2_tcpConnEntry *)data,
                                   len);
        }
        else if ((op->level == MIB2_UDP) &&
                 (op->name == MIB2_UDP_5) &&
                 want_udp)
        {
            status =
                udp_connection_get(walker,
                                   (struct mib2_udpEntry *)data,
                                   len);
        }
        else {
            status = SIGAR_OK;
        }

        if (status != SIGAR_OK) {
            break;
        }
    }

    if (rc != GET_MIB2_EOD) {
        close_mib2(&sigar->mib2);
        return SIGAR_EMIB2;
    }

    return SIGAR_OK;
}
