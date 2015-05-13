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

#include <net/if.h>
#include <sys/dk.h>
#ifndef __ia64__
#include <sys/lwp.h>
#endif
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _PSTAT64
typedef int64_t pstat_int_t;
#else
typedef int32_t pstat_int_t;
#endif

int sigar_os_open(sigar_t **sigar)
{
    *sigar = malloc(sizeof(**sigar));

    /* does not change while system is running */
    pstat_getstatic(&(*sigar)->pstatic,
                    sizeof((*sigar)->pstatic),
                    1, 0);

    (*sigar)->ticks = sysconf(_SC_CLK_TCK);

    (*sigar)->last_pid = -1;

    (*sigar)->pinfo = NULL;

    (*sigar)->mib = -1;

    return SIGAR_OK;

}

int sigar_os_close(sigar_t *sigar)
{
    if (sigar->pinfo) {
        free(sigar->pinfo);
    }
    if (sigar->mib >= 0) {
        close_mib(sigar->mib);
    }
    free(sigar);
    return SIGAR_OK;
}

char *sigar_os_error_string(sigar_t *sigar, int err)
{
    return NULL;
}

int sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem)
{
    struct pst_dynamic stats;
    struct pst_vminfo vminfo;
    sigar_uint64_t pagesize = sigar->pstatic.page_size;
    sigar_uint64_t kern;

    mem->total = sigar->pstatic.physical_memory * pagesize;

    pstat_getdynamic(&stats, sizeof(stats), 1, 0);

    mem->free = stats.psd_free * pagesize;
    mem->used = mem->total - mem->free;

    pstat_getvminfo(&vminfo, sizeof(vminfo), 1, 0);

    /* "kernel dynamic memory" */
    kern = vminfo.psv_kern_dynmem * pagesize;
    mem->actual_free = mem->free + kern;
    mem->actual_used = mem->used - kern;

    sigar_mem_calc_ram(sigar, mem);

    return SIGAR_OK;
}

int sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap)
{
    struct pst_swapinfo swapinfo;
    struct pst_vminfo vminfo;
    int i=0;

    swap->total = swap->free = 0;

    while (pstat_getswap(&swapinfo, sizeof(swapinfo), 1, i++) > 0) {
        swapinfo.pss_nfpgs *= 4;  /* nfpgs is in 512 byte blocks */

        if (swapinfo.pss_nblksenabled == 0) {
            swapinfo.pss_nblksenabled = swapinfo.pss_nfpgs;
        }

        swap->total += swapinfo.pss_nblksenabled;
        swap->free  += swapinfo.pss_nfpgs;
    }

    swap->used = swap->total - swap->free;

    pstat_getvminfo(&vminfo, sizeof(vminfo), 1, 0);

    swap->page_in = vminfo.psv_spgin;
    swap->page_out = vminfo.psv_spgout;

    return SIGAR_OK;
}

static void get_cpu_metrics(sigar_t *sigar,
                            sigar_cpu_t *cpu,
                            pstat_int_t *cpu_time)
{
    cpu->user = SIGAR_TICK2MSEC(cpu_time[CP_USER]);

    cpu->sys  = SIGAR_TICK2MSEC(cpu_time[CP_SYS] +
                                cpu_time[CP_SSYS]);

    cpu->nice = SIGAR_TICK2MSEC(cpu_time[CP_NICE]);

    cpu->idle = SIGAR_TICK2MSEC(cpu_time[CP_IDLE]);

    cpu->wait = SIGAR_TICK2MSEC(cpu_time[CP_SWAIT] +
                                cpu_time[CP_BLOCK]);

    cpu->irq = SIGAR_TICK2MSEC(cpu_time[CP_INTR]);
    cpu->soft_irq = 0; /*N/A*/
    cpu->stolen = 0; /*N/A*/

    cpu->total =
        cpu->user + cpu->sys + cpu->nice + cpu->idle + cpu->wait + cpu->irq;
}

int sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    struct pst_dynamic stats;

    pstat_getdynamic(&stats, sizeof(stats), 1, 0);
    sigar->ncpu = stats.psd_proc_cnt;

    get_cpu_metrics(sigar, cpu, stats.psd_cpu_time);

    return SIGAR_OK;
}

#define PROC_ELTS 16

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist)
{
    int num, idx=0;
    struct pst_status proctab[PROC_ELTS];

    while ((num = pstat_getproc(proctab, sizeof(proctab[0]),
                                PROC_ELTS, idx)) > 0)
    {
        int i;

        for (i=0; i<num; i++) {
            SIGAR_PROC_LIST_GROW(proclist);
            proclist->data[proclist->number++] =
                proctab[i].pst_pid;
        }

        idx = proctab[num-1].pst_idx + 1;
    }

    if (proclist->number == 0) {
        return errno;
    }

    return SIGAR_OK;
}

static int sigar_pstat_getproc(sigar_t *sigar, sigar_pid_t pid)
{
    int status, num;
    time_t timenow = time(NULL);

    if (sigar->pinfo == NULL) {
        sigar->pinfo = malloc(sizeof(*sigar->pinfo));
    }

    if (sigar->last_pid == pid) {
        if ((timenow - sigar->last_getprocs) < SIGAR_LAST_PROC_EXPIRE) {
            return SIGAR_OK;
        }
    }

    sigar->last_pid = pid;
    sigar->last_getprocs = timenow;

    if (pstat_getproc(sigar->pinfo,
                      sizeof(*sigar->pinfo),
                      0, pid) == -1)
    {
        return errno;
    }

    return SIGAR_OK;
}

int sigar_proc_mem_get(sigar_t *sigar, sigar_pid_t pid,
                       sigar_proc_mem_t *procmem)
{
    int pagesize = sigar->pstatic.page_size;
    int status = sigar_pstat_getproc(sigar, pid);
    struct pst_status *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    procmem->size =
        pinfo->pst_vtsize + /* text */
        pinfo->pst_vdsize + /* data */
        pinfo->pst_vssize + /* stack */
        pinfo->pst_vshmsize + /* shared memory */
        pinfo->pst_vmmsize + /* mem-mapped files */
        pinfo->pst_vusize + /* U-Area & K-Stack */
        pinfo->pst_viosize; /* I/O dev mapping */

    procmem->size *= pagesize;

    procmem->resident = pinfo->pst_rssize * pagesize;

    procmem->share = pinfo->pst_vshmsize * pagesize;

    procmem->minor_faults = pinfo->pst_minorfaults;
    procmem->major_faults = pinfo->pst_majorfaults;
    procmem->page_faults =
        procmem->minor_faults +
        procmem->major_faults;

    return SIGAR_OK;
}

int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_time_t *proctime)
{
    int status = sigar_pstat_getproc(sigar, pid);
    struct pst_status *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    proctime->start_time = pinfo->pst_start;
    proctime->start_time *= SIGAR_MSEC;
    proctime->user = pinfo->pst_utime * SIGAR_MSEC;
    proctime->sys  = pinfo->pst_stime * SIGAR_MSEC;
    proctime->total = proctime->user + proctime->sys;

    return SIGAR_OK;
}

int sigar_proc_state_get(sigar_t *sigar, sigar_pid_t pid,
                         sigar_proc_state_t *procstate)
{
    int status = sigar_pstat_getproc(sigar, pid);
    struct pst_status *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }


    SIGAR_SSTRCPY(procstate->name, pinfo->pst_ucomm);
    procstate->ppid = pinfo->pst_ppid;
    procstate->tty  = makedev(pinfo->pst_term.psd_major,
                              pinfo->pst_term.psd_minor);
    procstate->priority = pinfo->pst_pri;
    procstate->nice     = pinfo->pst_nice;
    procstate->threads  = pinfo->pst_nlwps;
    procstate->processor = pinfo->pst_procnum;

    /* cast to prevent compiler warning: */
    /* Case label too big for the type of the switch expression */
    switch ((int32_t)pinfo->pst_stat) {
      case PS_SLEEP:
        procstate->state = 'S';
        break;
      case PS_RUN:
        procstate->state = 'R';
        break;
      case PS_STOP:
        procstate->state = 'T';
        break;
      case PS_ZOMBIE:
        procstate->state = 'Z';
        break;
      case PS_IDLE:
        procstate->state = 'D';
        break;
    }

    return SIGAR_OK;
}


#define TIME_NSEC(t) \
    (SIGAR_SEC2NANO((t).tv_sec) + (sigar_uint64_t)(t).tv_nsec)

#include <mntent.h>

int sigar_os_fs_type_get(sigar_file_system_t *fsp)
{
    char *type = fsp->sys_type_name;

    switch (*type) {
      case 'h':
        if (strEQ(type, "hfs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
      case 'c':
        if (strEQ(type, "cdfs")) {
            fsp->type = SIGAR_FSTYPE_CDROM;
        }
        break;
    }

    return fsp->type;
}

int sigar_file_system_list_get(sigar_t *sigar,
                               sigar_file_system_list_t *fslist)
{
    struct mntent *ent;

    FILE *fp;
    sigar_file_system_t *fsp;

    if (!(fp = setmntent(MNT_MNTTAB, "r"))) {
        return errno;
    }

    sigar_file_system_list_create(fslist);

    while ((ent = getmntent(fp))) {
        if ((*(ent->mnt_type) == 's') &&
            strEQ(ent->mnt_type, "swap"))
        {
            /*
             * in this case, devname == "...", for
             * which statfs chokes on.  so skip it.
             * also notice hpux df command has no swap info.
             */
            continue;
        }

        SIGAR_FILE_SYSTEM_LIST_GROW(fslist);

        fsp = &fslist->data[fslist->number++];

        SIGAR_SSTRCPY(fsp->dir_name, ent->mnt_dir);
        SIGAR_SSTRCPY(fsp->dev_name, ent->mnt_fsname);
        SIGAR_SSTRCPY(fsp->sys_type_name, ent->mnt_type);
        SIGAR_SSTRCPY(fsp->options, ent->mnt_opts);
        sigar_fs_type_init(fsp);
    }

    endmntent(fp);

    return SIGAR_OK;
}

static int create_fsdev_cache(sigar_t *sigar)
{
    sigar_file_system_list_t fslist;
    int i;
    int status =
        sigar_file_system_list_get(sigar, &fslist);

    if (status != SIGAR_OK) {
        return status;
    }

    sigar->fsdev = sigar_cache_new(15);

    for (i=0; i<fslist.number; i++) {
        sigar_file_system_t *fsp = &fslist.data[i];

        if (fsp->type == SIGAR_FSTYPE_LOCAL_DISK) {
            sigar_cache_entry_t *ent;
            struct stat sb;

            if (stat(fsp->dir_name, &sb) < 0) {
                continue;
            }

            ent = sigar_cache_get(sigar->fsdev, SIGAR_FSDEV_ID(sb));
            ent->value = strdup(fsp->dev_name);
        }
    }

    return SIGAR_OK;
}

static int sigar_get_mib_info(sigar_t *sigar,
                              struct nmparms *parms)
{
    if (sigar->mib < 0) {
        if ((sigar->mib = open_mib("/dev/ip", O_RDONLY, 0, 0)) < 0) {
            return errno;
        }
    }
    return get_mib_info(sigar->mib, parms);
}

/* wrapper around get_physical_stat() */
static int sigar_get_physical_stat(sigar_t *sigar, int *count)
{
    int status;
    unsigned int len;
    struct nmparms parms;

    len = sizeof(*count);
    parms.objid = ID_ifNumber;
    parms.buffer = count;
    parms.len = &len;

    if ((status = sigar_get_mib_info(sigar, &parms)) != SIGAR_OK) {
        return status;
    }

    len = sizeof(nmapi_phystat) * *count;

    if (sigar->ifconf_len < len) {
        sigar->ifconf_buf = realloc(sigar->ifconf_buf, len);
        sigar->ifconf_len = len;
    }

    if (get_physical_stat(sigar->ifconf_buf, &len) < 0) {
        return errno;
    }
    else {
        return SIGAR_OK;
    }
}

#define SIGAR_IF_NAMESIZE 16
/* hpux if_indextoname() does not work as advertised in 11.11 */
static int sigar_if_indextoname(sigar_t *sigar,
                                char *name,
                                int index)
{
    int i, status, count;
    nmapi_phystat *stat;

    if ((status = sigar_get_physical_stat(sigar, &count) != SIGAR_OK)) {
        return status;
    }

    for (i=0, stat = (nmapi_phystat *)sigar->ifconf_buf;
         i<count;
         i++, stat++)
    {
        if (stat->if_entry.ifIndex == index) {
            strncpy(name, stat->nm_device, SIGAR_IF_NAMESIZE);
            return SIGAR_OK;
        }
    }

    return ENXIO;
}

static int get_mib_ifstat(sigar_t *sigar,
                          const char *name,
                          mib_ifEntry *mib)
{
    int i, status, count;
    nmapi_phystat *stat;

    if ((status = sigar_get_physical_stat(sigar, &count) != SIGAR_OK)) {
        return status;
    }

    for (i=0, stat = (nmapi_phystat *)sigar->ifconf_buf;
         i<count;
         i++, stat++)
    {
        if (strEQ(stat->nm_device, name)) {
            memcpy(mib, &stat->if_entry, sizeof(*mib));
            return SIGAR_OK;
        }
    }

    return ENXIO;
}


int sigar_net_interface_ipv6_config_get(sigar_t *sigar, const char *name,
                                        sigar_net_interface_config_t *ifconfig)
{
    int sock;
    struct if_laddrreq iflr;

    if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        return errno;
    }

    SIGAR_SSTRCPY(iflr.iflr_name, name);

    if (ioctl(sock, SIOCGLIFADDR, &iflr) == 0) {
        struct in6_addr *addr = SIGAR_SIN6_ADDR(&iflr.iflr_addr);

        sigar_net_address6_set(ifconfig->address6, addr);
        sigar_net_interface_scope6_set(ifconfig, addr);

        if (ioctl(sock, SIOCGLIFNETMASK, &iflr) == 0) {
            addr = SIGAR_SIN6_ADDR(&iflr.iflr_addr);
            ifconfig->prefix6_length = 10; /*XXX*/
        }
    }

    close(sock);
    return SIGAR_OK;
}

static int net_conn_get_udp_listen(sigar_net_connection_walker_t *walker)
{
    sigar_t *sigar = walker->sigar;
    int flags = walker->flags;
    int status, count, i;
    unsigned int len;
    mib_udpLsnEnt *entries;
    struct nmparms parms;

    len = sizeof(count);
    parms.objid = ID_udpLsnNumEnt;
    parms.buffer = &count;
    parms.len = &len;

    if ((status = sigar_get_mib_info(sigar, &parms)) != SIGAR_OK) {
        return status;
    }

    if (count <= 0) {
        return ENOENT;
    }

    len =  count * sizeof(*entries);
    entries = malloc(len);
    parms.objid = ID_udpLsnTable;
    parms.buffer = entries;
    parms.len = &len;

    if ((status = sigar_get_mib_info(sigar, &parms)) != SIGAR_OK) {
        free(entries);
        return status;
    }

    for (i=0; i<count; i++) {
        sigar_net_connection_t conn;
        mib_udpLsnEnt *entry = &entries[i];

        SIGAR_ZERO(&conn);

        conn.type = SIGAR_NETCONN_UDP;

        conn.local_port  = (unsigned short)entry->LocalPort;
        conn.remote_port = 0;

        sigar_net_address_set(conn.local_address,
                              entry->LocalAddress);

        sigar_net_address_set(conn.remote_address, 0);

        conn.send_queue = conn.receive_queue = SIGAR_FIELD_NOTIMPL;

        if (walker->add_connection(walker, &conn) != SIGAR_OK) {
            break;
        }
    }

    free(entries);
    return SIGAR_OK;
}

static int net_conn_get_udp(sigar_net_connection_walker_t *walker)
{
    int status = SIGAR_OK;

    if (walker->flags & SIGAR_NETCONN_SERVER) {
        status = net_conn_get_udp_listen(walker);
    }

    return status;
}

#define IS_TCP_SERVER(state, flags) \
    ((flags & SIGAR_NETCONN_SERVER) && (state == TCLISTEN))

#define IS_TCP_CLIENT(state, flags) \
    ((flags & SIGAR_NETCONN_CLIENT) && (state != TCLISTEN))

static int net_conn_get_tcp(sigar_net_connection_walker_t *walker)
{
    sigar_t *sigar = walker->sigar;
    int flags = walker->flags;
    int status, count, i;
    unsigned int len;
    mib_tcpConnEnt *entries;
    struct nmparms parms;

    len = sizeof(count);
    parms.objid = ID_tcpConnNumEnt;
    parms.buffer = &count;
    parms.len = &len;

    if ((status = sigar_get_mib_info(sigar, &parms)) != SIGAR_OK) {
        return status;
    }

    if (count <= 0) {
        return ENOENT;
    }

    len =  count * sizeof(*entries);
    entries = malloc(len);
    parms.objid = ID_tcpConnTable;
    parms.buffer = entries;
    parms.len = &len;

    if ((status = sigar_get_mib_info(sigar, &parms)) != SIGAR_OK) {
        free(entries);
        return status;
    }

    for (i=0; i<count; i++) {
        sigar_net_connection_t conn;
        mib_tcpConnEnt *entry = &entries[i];
        int state = entry->State;

        if (!(IS_TCP_SERVER(state, flags) ||
              IS_TCP_CLIENT(state, flags)))
        {
            continue;
        }

        SIGAR_ZERO(&conn);

        switch (state) {
          case TCCLOSED:
            conn.state = SIGAR_TCP_CLOSE;
            break;
          case TCLISTEN:
            conn.state = SIGAR_TCP_LISTEN;
            break;
          case TCSYNSENT:
            conn.state = SIGAR_TCP_SYN_SENT;
            break;
          case TCSYNRECEIVE:
            conn.state = SIGAR_TCP_SYN_RECV;
            break;
          case TCESTABLISED:
            conn.state = SIGAR_TCP_ESTABLISHED;
            break;
          case TCFINWAIT1:
            conn.state = SIGAR_TCP_FIN_WAIT1;
            break;
          case TCFINWAIT2:
            conn.state = SIGAR_TCP_FIN_WAIT2;
            break;
          case TCCLOSEWAIT:
            conn.state = SIGAR_TCP_CLOSE_WAIT;
            break;
          case TCCLOSING:
            conn.state = SIGAR_TCP_CLOSING;
            break;
          case TCLASTACK:
            conn.state = SIGAR_TCP_LAST_ACK;
            break;
          case TCTIMEWAIT:
            conn.state = SIGAR_TCP_TIME_WAIT;
            break;
          case TCDELETETCB:
          default:
            conn.state = SIGAR_TCP_UNKNOWN;
            break;
        }

        conn.local_port  = (unsigned short)entry->LocalPort;
        conn.remote_port = (unsigned short)entry->RemPort;
        conn.type = SIGAR_NETCONN_TCP;

        sigar_net_address_set(conn.local_address, entry->LocalAddress);
        sigar_net_address_set(conn.remote_address, entry->RemAddress);

        conn.send_queue = conn.receive_queue = SIGAR_FIELD_NOTIMPL;

        if (walker->add_connection(walker, &conn) != SIGAR_OK) {
            break;
        }
    }

    free(entries);

    return SIGAR_OK;
}

int sigar_net_connection_walk(sigar_net_connection_walker_t *walker)
{
    int status;

    if (walker->flags & SIGAR_NETCONN_TCP) {
        status = net_conn_get_tcp(walker);

        if (status != SIGAR_OK) {
            return status;
        }
    }

    if (walker->flags & SIGAR_NETCONN_UDP) {
        status = net_conn_get_udp(walker);

        if (status != SIGAR_OK) {
            return status;
        }
    }

    return SIGAR_OK;
}

#define tcpsoff(x) sigar_offsetof(sigar_tcp_t, x)

static struct {
    unsigned int id;
    size_t offset;
} tcps_lu[] = {
#if 0
    { ID_tcpRtoAlgorithm, tcpsoff(xxx) },
    { ID_tcpRtoMin, tcpsoff(xxx) },
    { ID_tcpRtoMax, tcpsoff(xxx) },
    { ID_tcpMaxConn, tcpsoff(max_conn) },
#endif
    { ID_tcpActiveOpens, tcpsoff(active_opens) },
    { ID_tcpPassiveOpens, tcpsoff(passive_opens) },
    { ID_tcpAttemptFails, tcpsoff(attempt_fails) },
    { ID_tcpEstabResets, tcpsoff(estab_resets) },
    { ID_tcpCurrEstab, tcpsoff(curr_estab) },
    { ID_tcpInSegs, tcpsoff(in_segs) },
    { ID_tcpOutSegs, tcpsoff(out_segs) },
    { ID_tcpRetransSegs, tcpsoff(retrans_segs) },
    { ID_tcpInErrs, tcpsoff(in_errs) },
    { ID_tcpOutRsts, tcpsoff(out_rsts) }
};
