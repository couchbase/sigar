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

#include <errno.h>
#include <stdio.h>

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#if defined(__OpenBSD__) || defined(__FreeBSD__)
#include <netinet/in.h>
#endif
#ifndef WIN32
#include <arpa/inet.h>
#endif

#include "sigar.h"
#include "sigar_private.h"
#include "sigar_util.h"
#include "sigar_os.h"
#include "sigar_format.h"

SIGAR_DECLARE(int) sigar_open(sigar_t **sigar)
{
    int status = sigar_os_open(sigar);

    if (status == SIGAR_OK) {
        /* use env to revert to old behavior */
        (*sigar)->pid = 0;
        (*sigar)->ifconf_buf = NULL;
        (*sigar)->ifconf_len = 0;
        (*sigar)->log_level = -1; /* log nothing by default */
        (*sigar)->log_impl = NULL;
        (*sigar)->log_data = NULL;
        (*sigar)->ptql_re_impl = NULL;
        (*sigar)->ptql_re_data = NULL;
        (*sigar)->self_path = NULL;
        (*sigar)->fsdev = NULL;
        (*sigar)->pids = NULL;
        (*sigar)->proc_cpu = NULL;
        (*sigar)->net_listen = NULL;
        (*sigar)->net_services_tcp = NULL;
        (*sigar)->net_services_udp = NULL;
    }

    return status;
}

SIGAR_DECLARE(int) sigar_close(sigar_t *sigar)
{
    if (sigar->ifconf_buf) {
        free(sigar->ifconf_buf);
    }
    if (sigar->self_path) {
        free(sigar->self_path);
    }
    if (sigar->pids) {
        sigar_proc_list_destroy(sigar, sigar->pids);
        free(sigar->pids);
    }
    if (sigar->fsdev) {
        sigar_cache_destroy(sigar->fsdev);
    }
    if (sigar->proc_cpu) {
        sigar_cache_destroy(sigar->proc_cpu);
    }
    if (sigar->net_listen) {
        sigar_cache_destroy(sigar->net_listen);
    }
    if (sigar->net_services_tcp) {
        sigar_cache_destroy(sigar->net_services_tcp);
    }
    if (sigar->net_services_udp) {
        sigar_cache_destroy(sigar->net_services_udp);
    }

    return sigar_os_close(sigar);
}

#ifdef WIN32
#include <process.h>
#endif

#ifndef __linux__ /* linux has a special case */
SIGAR_DECLARE(sigar_pid_t) sigar_pid_get(sigar_t *sigar)
{
    if (!sigar->pid) {
        sigar->pid = getpid();
    }

    return sigar->pid;
}
#endif

/* XXX: add clear() function */
/* XXX: check for stale-ness using start_time */
SIGAR_DECLARE(int) sigar_proc_cpu_get(sigar_t *sigar, sigar_pid_t pid,
                                      sigar_proc_cpu_t *proccpu)
{
    sigar_cache_entry_t *entry;
    sigar_proc_cpu_t *prev;
    sigar_uint64_t otime, time_now = sigar_time_now_millis();
    sigar_uint64_t time_diff, total_diff;
    int status;

    if (!sigar->proc_cpu) {
        sigar->proc_cpu = sigar_cache_new(128);
    }

    entry = sigar_cache_get(sigar->proc_cpu, pid);
    if (entry->value) {
        prev = (sigar_proc_cpu_t *)entry->value;
    }
    else {
        prev = entry->value = malloc(sizeof(*prev));
        SIGAR_ZERO(prev);
    }

    time_diff = time_now - prev->last_time;
    proccpu->last_time = time_now;

    if (time_diff < 1000) {
        /* we were just called within < 1 second ago. */
        memcpy(proccpu, prev, sizeof(*proccpu));
        return SIGAR_OK;
    }

    otime = prev->total;

    status =
        sigar_proc_time_get(sigar, pid,
                            (sigar_proc_time_t *)proccpu);

    if (status != SIGAR_OK) {
        return status;
    }

    if (proccpu->total < otime) {
        /* XXX this should not happen */
        otime = 0;
    }

    if (otime == 0) {
        /* first time called */
        proccpu->percent = 0.0;
    } else {
        total_diff = proccpu->total - otime;
        proccpu->percent = total_diff / (double)time_diff;
    }

    memcpy(prev, proccpu, sizeof(*prev));

    return SIGAR_OK;
}

int sigar_proc_list_create(sigar_proc_list_t *proclist)
{
    proclist->number = 0;
    proclist->size = SIGAR_PROC_LIST_MAX;
    proclist->data = malloc(sizeof(*(proclist->data)) *
                            proclist->size);
    return SIGAR_OK;
}

int sigar_proc_list_grow(sigar_proc_list_t *proclist)
{
    proclist->data = realloc(proclist->data,
                             sizeof(*(proclist->data)) *
                             (proclist->size + SIGAR_PROC_LIST_MAX));
    proclist->size += SIGAR_PROC_LIST_MAX;

    return SIGAR_OK;
}

SIGAR_DECLARE(int) sigar_proc_list_destroy(sigar_t *sigar,
                                           sigar_proc_list_t *proclist)
{
    if (proclist->size) {
        free(proclist->data);
        proclist->number = proclist->size = 0;
    }

    return SIGAR_OK;
}

SIGAR_DECLARE(int) sigar_proc_list_get(sigar_t *sigar,
                                       sigar_proc_list_t *proclist)
{
    if (proclist == NULL) {
        /* internal re-use */
        if (sigar->pids == NULL) {
            sigar->pids = malloc(sizeof(*sigar->pids));
            sigar_proc_list_create(sigar->pids);
        }
        else {
            sigar->pids->number = 0;
        }
        proclist = sigar->pids;
    }
    else {
        sigar_proc_list_create(proclist);
    }

    return sigar_os_proc_list_get(sigar, proclist);
}

SIGAR_DECLARE(int)
sigar_proc_list_get_children(sigar_t* sigar,
                             sigar_pid_t ppid,
                             sigar_proc_list_t* proclist) {
    if (proclist == NULL) {
        /* internal re-use */
        if (sigar->pids == NULL) {
            sigar->pids = malloc(sizeof(*sigar->pids));
            sigar_proc_list_create(sigar->pids);
        } else {
            sigar->pids->number = 0;
        }
        proclist = sigar->pids;
    } else {
        sigar_proc_list_create(proclist);
    }

    return sigar_os_proc_list_get_children(sigar, ppid, proclist);
}

int sigar_proc_args_create(sigar_proc_args_t *procargs)
{
    procargs->number = 0;
    procargs->size = SIGAR_PROC_ARGS_MAX;
    procargs->data = malloc(sizeof(*(procargs->data)) *
                            procargs->size);
    return SIGAR_OK;
}

int sigar_proc_args_grow(sigar_proc_args_t *procargs)
{
    procargs->data = realloc(procargs->data,
                             sizeof(*(procargs->data)) *
                             (procargs->size + SIGAR_PROC_ARGS_MAX));
    procargs->size += SIGAR_PROC_ARGS_MAX;

    return SIGAR_OK;
}


int sigar_file_system_list_create(sigar_file_system_list_t *fslist)
{
    fslist->number = 0;
    fslist->size = SIGAR_FS_MAX;
    fslist->data = malloc(sizeof(*(fslist->data)) *
                          fslist->size);
    return SIGAR_OK;
}

int sigar_file_system_list_grow(sigar_file_system_list_t *fslist)
{
    fslist->data = realloc(fslist->data,
                           sizeof(*(fslist->data)) *
                           (fslist->size + SIGAR_FS_MAX));
    fslist->size += SIGAR_FS_MAX;

    return SIGAR_OK;
}

/* indexed with sigar_file_system_type_e */
static const char *fstype_names[] = {
    "unknown", "none", "local", "remote", "ram", "cdrom", "swap"
};

static int sigar_common_fs_type_get(sigar_file_system_t *fsp)
{
    char *type = fsp->sys_type_name;

    switch (*type) {
      case 'n':
        if (strnEQ(type, "nfs", 3)) {
            fsp->type = SIGAR_FSTYPE_NETWORK;
        }
        break;
      case 's':
        if (strEQ(type, "smbfs")) { /* samba */
            fsp->type = SIGAR_FSTYPE_NETWORK;
        }
        else if (strEQ(type, "swap")) {
            fsp->type = SIGAR_FSTYPE_SWAP;
        }
        break;
      case 'a':
        if (strEQ(type, "afs")) {
            fsp->type = SIGAR_FSTYPE_NETWORK;
        }
        break;
      case 'i':
        if (strEQ(type, "iso9660")) {
            fsp->type = SIGAR_FSTYPE_CDROM;
        }
        break;
      case 'c':
        if (strEQ(type, "cvfs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        else if (strEQ(type, "cifs")) {
            fsp->type = SIGAR_FSTYPE_NETWORK;
        }
        break;
      case 'm':
        if (strEQ(type, "msdos") || strEQ(type, "minix")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
      case 'h':
        if (strEQ(type, "hpfs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
      case 'v':
        if (strEQ(type, "vxfs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        else if (strEQ(type, "vfat")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
      case 'z':
        if (strEQ(type, "zfs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
    }

    return fsp->type;
}

void sigar_fs_type_get(sigar_file_system_t *fsp)
{
    if (!(fsp->type ||                    /* already set */
          sigar_os_fs_type_get(fsp) ||    /* try os specifics first */
          sigar_common_fs_type_get(fsp))) /* try common ones last */
    {
        fsp->type = SIGAR_FSTYPE_NONE;
    }

    if (fsp->type >= SIGAR_FSTYPE_MAX) {
        fsp->type = SIGAR_FSTYPE_NONE;
    }

    strcpy(fsp->type_name, fstype_names[fsp->type]);
}


SIGAR_DECLARE(int)
sigar_file_system_list_destroy(sigar_t *sigar,
                               sigar_file_system_list_t *fslist)
{
    if (fslist->size) {
        free(fslist->data);
        fslist->number = fslist->size = 0;
    }

    return SIGAR_OK;
}

int sigar_net_interface_list_create(sigar_net_interface_list_t *iflist)
{
    iflist->number = 0;
    iflist->size = SIGAR_NET_IFLIST_MAX;
    iflist->data = malloc(sizeof(*(iflist->data)) *
                          iflist->size);
    return SIGAR_OK;
}

int sigar_net_interface_list_grow(sigar_net_interface_list_t *iflist)
{
    iflist->data = realloc(iflist->data,
                           sizeof(*(iflist->data)) *
                           (iflist->size + SIGAR_NET_IFLIST_MAX));
    iflist->size += SIGAR_NET_IFLIST_MAX;

    return SIGAR_OK;
}

SIGAR_DECLARE(int)
sigar_net_interface_list_destroy(sigar_t *sigar,
                                 sigar_net_interface_list_t *iflist)
{
    unsigned int i;

    if (iflist->size) {
        for (i=0; i<iflist->number; i++) {
            free(iflist->data[i]);
        }
        free(iflist->data);
        iflist->number = iflist->size = 0;
    }

    return SIGAR_OK;
}

int sigar_net_connection_list_create(sigar_net_connection_list_t *connlist)
{
    connlist->number = 0;
    connlist->size = SIGAR_NET_CONNLIST_MAX;
    connlist->data = malloc(sizeof(*(connlist->data)) *
                            connlist->size);
    return SIGAR_OK;
}

int sigar_net_connection_list_grow(sigar_net_connection_list_t *connlist)
{
    connlist->data =
        realloc(connlist->data,
                sizeof(*(connlist->data)) *
                (connlist->size + SIGAR_NET_CONNLIST_MAX));
    connlist->size += SIGAR_NET_CONNLIST_MAX;

    return SIGAR_OK;
}

SIGAR_DECLARE(int)
sigar_net_connection_list_destroy(sigar_t *sigar,
                                  sigar_net_connection_list_t *connlist)
{
    if (connlist->size) {
        free(connlist->data);
        connlist->number = connlist->size = 0;
    }

    return SIGAR_OK;
}

#if !defined(__linux__)
/*
 * implement sigar_net_connection_list_get using sigar_net_connection_walk
 * linux has its own list_get impl.
 */
static int net_connection_list_walker(sigar_net_connection_walker_t *walker,
                                      sigar_net_connection_t *conn)
{
    sigar_net_connection_list_t *connlist =
        (sigar_net_connection_list_t *)walker->data;

    SIGAR_NET_CONNLIST_GROW(connlist);
    memcpy(&connlist->data[connlist->number++],
           conn, sizeof(*conn));

    return SIGAR_OK; /* continue loop */
}

SIGAR_DECLARE(int)
sigar_net_connection_list_get(sigar_t *sigar,
                              sigar_net_connection_list_t *connlist,
                              int flags)
{
    int status;
    sigar_net_connection_walker_t walker;

    sigar_net_connection_list_create(connlist);

    walker.sigar = sigar;
    walker.flags = flags;
    walker.data = connlist;
    walker.add_connection = net_connection_list_walker;

    status = sigar_net_connection_walk(&walker);

    if (status != SIGAR_OK) {
        sigar_net_connection_list_destroy(sigar, connlist);
    }

    return status;
}
#endif

#ifdef DARWIN
#include <AvailabilityMacros.h>
#endif
#ifdef MAC_OS_X_VERSION_10_5
#  if MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_5
#    define SIGAR_NO_UTMP
#  endif
/* else 10.4 and earlier or compiled with -mmacosx-version-min=10.3 */
#endif

#ifndef WIN32
#include <sys/resource.h>
#endif

#ifdef HAVE_LIBDLPI_H
#include <libdlpi.h>

static void hwaddr_libdlpi_lookup(sigar_t *sigar, sigar_net_interface_config_t *ifconfig)
{
    dlpi_handle_t handle;
    dlpi_info_t linkinfo;
    uchar_t addr[DLPI_PHYSADDR_MAX];
    uint_t alen = sizeof(addr);

    if (dlpi_open(ifconfig->name, &handle, 0) != DLPI_SUCCESS) {
        return;
    }

    if (dlpi_get_physaddr(handle, DL_CURR_PHYS_ADDR, addr, &alen) == DLPI_SUCCESS &&
        dlpi_info(handle, &linkinfo, 0) == DLPI_SUCCESS) {
        if (alen < sizeof(ifconfig->hwaddr.addr.mac)) {
            sigar_net_address_mac_set(ifconfig->hwaddr, addr, alen);
            SIGAR_SSTRCPY(ifconfig->type, dlpi_mactype(linkinfo.di_mactype));
        }
    }

    dlpi_close(handle);
}
#endif


#if !defined(WIN32) && !defined(NETWARE) && !defined(DARWIN) && \
    !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__)

/* XXX: prolly will be moving these stuffs into os_net.c */
#include <sys/ioctl.h>
#include <net/if.h>

#ifndef SIOCGIFCONF
#include <sys/sockio.h>
#endif

#if defined(_AIX) || defined(__osf__) /* good buddies */

#include <net/if_dl.h>

static void hwaddr_aix_lookup(sigar_t *sigar, sigar_net_interface_config_t *ifconfig)
{
    char *ent, *end;
    struct ifreq *ifr;

    /* XXX: assumes sigar_net_interface_list_get has been called */
    end = sigar->ifconf_buf + sigar->ifconf_len;

    for (ent = sigar->ifconf_buf;
         ent < end;
         ent += sizeof(*ifr))
    {
        ifr = (struct ifreq *)ent;

        if (ifr->ifr_addr.sa_family != AF_LINK) {
            continue;
        }

        if (strEQ(ifr->ifr_name, ifconfig->name)) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)&ifr->ifr_addr;

            sigar_net_address_mac_set(ifconfig->hwaddr,
                                      LLADDR(sdl),
                                      sdl->sdl_alen);
            return;
        }
    }

    sigar_hwaddr_set_null(ifconfig);
}

#elif !defined(SIOCGIFHWADDR)

#include <net/if_arp.h>

static void hwaddr_arp_lookup(sigar_net_interface_config_t *ifconfig, int sock)
{
    struct arpreq areq;
    struct sockaddr_in *sa;

    memset(&areq, 0, sizeof(areq));
    sa = (struct sockaddr_in *)&areq.arp_pa;
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = ifconfig->address.addr.in;

    if (ioctl(sock, SIOCGARP, &areq) < 0) {
        /* ho-hum */
        sigar_hwaddr_set_null(ifconfig);
    }
    else {
        sigar_net_address_mac_set(ifconfig->hwaddr,
                                  areq.arp_ha.sa_data,
                                  SIGAR_IFHWADDRLEN);
    }
}

#endif

#ifdef __linux__

#include <net/if_arp.h>

#ifndef ARPHRD_CISCO /* not in 2.2 kernel headers */
#define ARPHRD_CISCO 513 /* Cisco HDLC. */
#endif

static void get_interface_type(sigar_net_interface_config_t *ifconfig,
                               int family)
{
    char *type;

    switch (family) {
      case ARPHRD_SLIP:
        type = SIGAR_NIC_SLIP;
        break;
      case ARPHRD_CSLIP:
        type = SIGAR_NIC_CSLIP;
        break;
      case ARPHRD_SLIP6:
        type = SIGAR_NIC_SLIP6;
        break;
      case ARPHRD_CSLIP6:
        type = SIGAR_NIC_CSLIP6;
        break;
      case ARPHRD_ADAPT:
        type = SIGAR_NIC_ADAPTIVE;
        break;
      case ARPHRD_ETHER:
        type = SIGAR_NIC_ETHERNET;
        break;
      case ARPHRD_ASH:
        type = SIGAR_NIC_ASH;
        break;
      case ARPHRD_FDDI:
        type = SIGAR_NIC_FDDI;
        break;
      case ARPHRD_HIPPI:
        type = SIGAR_NIC_HIPPI;
        break;
      case ARPHRD_AX25:
        type = SIGAR_NIC_AX25;
        break;
      case ARPHRD_ROSE:
        type = SIGAR_NIC_ROSE;
        break;
      case ARPHRD_NETROM:
        type = SIGAR_NIC_NETROM;
        break;
      case ARPHRD_X25:
        type = SIGAR_NIC_X25;
        break;
      case ARPHRD_TUNNEL:
        type = SIGAR_NIC_TUNNEL;
        break;
      case ARPHRD_PPP:
        type = SIGAR_NIC_PPP;
        break;
      case ARPHRD_CISCO:
        type = SIGAR_NIC_HDLC;
        break;
      case ARPHRD_LAPB:
        type = SIGAR_NIC_LAPB;
        break;
      case ARPHRD_ARCNET:
        type = SIGAR_NIC_ARCNET;
        break;
      case ARPHRD_DLCI:
        type = SIGAR_NIC_DLCI;
        break;
      case ARPHRD_FRAD:
        type = SIGAR_NIC_FRAD;
        break;
      case ARPHRD_SIT:
        type = SIGAR_NIC_SIT;
        break;
      case ARPHRD_IRDA:
        type = SIGAR_NIC_IRDA;
        break;
      case ARPHRD_ECONET:
        type = SIGAR_NIC_EC;
        break;
      default:
        type = SIGAR_NIC_UNSPEC;
        break;
    }

    SIGAR_SSTRCPY(ifconfig->type, type);
}

#endif

int sigar_net_interface_config_get(sigar_t *sigar, const char *name,
                                   sigar_net_interface_config_t *ifconfig)
{
    int sock;
    struct ifreq ifr;

    if (!name) {
        return sigar_net_interface_config_primary_get(sigar, ifconfig);
    }

    SIGAR_ZERO(ifconfig);

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return errno;
    }

    SIGAR_SSTRCPY(ifconfig->name, name);
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

    if (!ioctl(sock, SIOCGIFFLAGS, &ifr)) {
        sigar_uint64_t flags = ifr.ifr_flags;
#ifdef __linux__
# ifndef IFF_DYNAMIC
#  define IFF_DYNAMIC 0x8000 /* not in 2.2 kernel */
# endif /* IFF_DYNAMIC */
        int is_mcast = flags & IFF_MULTICAST;
        int is_slave = flags & IFF_SLAVE;
        int is_master = flags & IFF_MASTER;
        int is_dynamic = flags & IFF_DYNAMIC;
        /*
         * XXX: should just define SIGAR_IFF_*
         * and test IFF_* bits on given platform.
         * this is the only diff between solaris/hpux/linux
         * for the flags we care about.
         *
         */
        flags &= ~(IFF_MULTICAST|IFF_SLAVE|IFF_MASTER);
        if (is_mcast) {
            flags |= SIGAR_IFF_MULTICAST;
        }
        if (is_slave) {
            flags |= SIGAR_IFF_SLAVE;
        }
        if (is_master) {
            flags |= SIGAR_IFF_MASTER;
        }
        if (is_dynamic) {
            flags |= SIGAR_IFF_DYNAMIC;
        }
#endif
        ifconfig->flags = flags;
    }
    else {
        /* should always be able to get flags for existing device */
        /* other ioctls may fail if device is not enabled: ok */
        close(sock);
        return errno;
    }

    if (ifconfig->flags & IFF_LOOPBACK) {
        sigar_net_address_set(ifconfig->destination,
                              ifconfig->address.addr.in);
        sigar_net_address_set(ifconfig->broadcast, 0);
        sigar_hwaddr_set_null(ifconfig);
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

#if defined(HAVE_LIBDLPI_H)
        hwaddr_libdlpi_lookup(sigar, ifconfig);
#elif defined(SIOCGIFHWADDR)
        if (!ioctl(sock, SIOCGIFHWADDR, &ifr)) {
            get_interface_type(ifconfig,
                               ifr.ifr_hwaddr.sa_family);
            sigar_net_address_mac_set(ifconfig->hwaddr,
                                      ifr.ifr_hwaddr.sa_data,
                                      IFHWADDRLEN);
        }
#elif defined(_AIX) || defined(__osf__)
        hwaddr_aix_lookup(sigar, ifconfig);
        SIGAR_SSTRCPY(ifconfig->type,
                      SIGAR_NIC_ETHERNET);
#else
        hwaddr_arp_lookup(ifconfig, sock);
        SIGAR_SSTRCPY(ifconfig->type,
                      SIGAR_NIC_ETHERNET);
#endif
    }

#if defined(SIOCGLIFMTU) && !defined(__hpux)
    {
        struct lifreq lifr;
        SIGAR_SSTRCPY(lifr.lifr_name, name);
        if(!ioctl(sock, SIOCGLIFMTU, &lifr)) {
            ifconfig->mtu = lifr.lifr_mtu;
        }
    }
#elif defined(SIOCGIFMTU)
    if (!ioctl(sock, SIOCGIFMTU, &ifr)) {
#  if defined(__hpux)
        ifconfig->mtu = ifr.ifr_metric;
#  else
        ifconfig->mtu = ifr.ifr_mtu;
#endif
    }
#else
    ifconfig->mtu = 0; /*XXX*/
#endif

    if (!ioctl(sock, SIOCGIFMETRIC, &ifr)) {
        ifconfig->metric = ifr.ifr_metric ? ifr.ifr_metric : 1;
    }

#if defined(SIOCGIFTXQLEN)
    if (!ioctl(sock, SIOCGIFTXQLEN, &ifr)) {
        ifconfig->tx_queue_len = ifr.ifr_qlen;
    }
    else {
        ifconfig->tx_queue_len = -1; /* net-tools behaviour */
    }
#else
    ifconfig->tx_queue_len = -1;
#endif

    close(sock);

    /* XXX can we get a better description like win32? */
    SIGAR_SSTRCPY(ifconfig->description,
                  ifconfig->name);

    sigar_net_interface_ipv6_config_init(ifconfig);
    sigar_net_interface_ipv6_config_get(sigar, name, ifconfig);

    return SIGAR_OK;
}

#ifdef _AIX
#  define MY_SIOCGIFCONF CSIOCGIFCONF
#else
#  define MY_SIOCGIFCONF SIOCGIFCONF
#endif

#ifdef __osf__
static int sigar_netif_configured(sigar_t *sigar, char *name)
{
    int status;
    sigar_net_interface_config_t ifconfig;

    status = sigar_net_interface_config_get(sigar, name, &ifconfig);

    return status == SIGAR_OK;
}
#endif

#ifdef __linux__
static  int has_interface(sigar_net_interface_list_t *iflist,
                                      char *name)
{
    register int i;
    register int num = iflist->number;
    register char **data = iflist->data;
    for (i=0; i<num; i++) {
        if (strEQ(name, data[i])) {
            return 1;
        }
    }
    return 0;
}

static int proc_net_interface_list_get(sigar_t *sigar,
                                       sigar_net_interface_list_t *iflist)
{
    /* certain interfaces such as VMware vmnic
     * are not returned by ioctl(SIOCGIFCONF).
     * check /proc/net/dev for any ioctl missed.
     */
    char buffer[BUFSIZ];
    FILE *fp = fopen("/proc/net/dev", "r");

    if (!fp) {
        return errno;
    }

    /* skip header */
    if (fgets(buffer, sizeof(buffer), fp) == NULL ||
        fgets(buffer, sizeof(buffer), fp) == NULL) {
        fclose(fp);
        return errno;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        char *ptr, *dev;

        dev = buffer;
        while (isspace(*dev)) {
            dev++;
        }

        if (!(ptr = strchr(dev, ':'))) {
            continue;
        }

        *ptr++ = 0;

        if (has_interface(iflist, dev)) {
            continue;
        }

        SIGAR_NET_IFLIST_GROW(iflist);

        iflist->data[iflist->number++] =
            sigar_strdup(dev);
    }

    fclose(fp);

    return SIGAR_OK;
}
#endif

int sigar_net_interface_list_get(sigar_t *sigar,
                                 sigar_net_interface_list_t *iflist)
{
    int n, lastlen=0;
    struct ifreq *ifr;
    struct ifconf ifc;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        return errno;
    }

    for (;;) {
        if (!sigar->ifconf_buf || lastlen) {
            sigar->ifconf_len += sizeof(struct ifreq) * SIGAR_NET_IFLIST_MAX;
            sigar->ifconf_buf = realloc(sigar->ifconf_buf, sigar->ifconf_len);
        }

        ifc.ifc_len = sigar->ifconf_len;
        ifc.ifc_buf = sigar->ifconf_buf;

        if (ioctl(sock, MY_SIOCGIFCONF, &ifc) < 0) {
            /* EINVAL should mean num_interfaces > ifc.ifc_len */
            if ((errno != EINVAL) ||
                (lastlen == ifc.ifc_len))
            {
                free(ifc.ifc_buf);
                return errno;
            }
        }

        if (ifc.ifc_len < sigar->ifconf_len) {
            break; /* got em all */
        }

        if (ifc.ifc_len != lastlen) {
            /* might be more */
            lastlen = ifc.ifc_len;
            continue;
        }

        break;
    }

    close(sock);

    iflist->number = 0;
    iflist->size = ifc.ifc_len;
    iflist->data = malloc(sizeof(*(iflist->data)) *
                          iflist->size);

    ifr = ifc.ifc_req;
    for (n = 0; n < ifc.ifc_len; n += sizeof(struct ifreq), ifr++) {
#if defined(_AIX) || defined(__osf__) /* pass the bourbon */
        if (ifr->ifr_addr.sa_family != AF_LINK) {
            /* XXX: dunno if this is right.
             * otherwise end up with two 'en0' and three 'lo0'
             * with the same ip address.
             */
            continue;
        }
#   ifdef __osf__
        /* weed out "sl0", "tun0" and the like */
        /* XXX must be a better way to check this */
        if (!sigar_netif_configured(sigar, ifr->ifr_name)) {
            continue;
        }
#   endif
#endif
        iflist->data[iflist->number++] =
            sigar_strdup(ifr->ifr_name);
    }

#ifdef __linux__
    proc_net_interface_list_get(sigar, iflist);
#endif

    return SIGAR_OK;
}

#endif /* WIN32 */

SIGAR_DECLARE(int)
sigar_net_interface_config_primary_get(sigar_t *sigar,
                                       sigar_net_interface_config_t *ifconfig)
{
    int i, status, found=0;
    sigar_net_interface_list_t iflist;
    sigar_net_interface_config_t possible_config;

    possible_config.flags = 0;

    if ((status = sigar_net_interface_list_get(sigar, &iflist)) != SIGAR_OK) {
        return status;
    }

    for (i=0; i<iflist.number; i++) {
        status = sigar_net_interface_config_get(sigar,
                                                iflist.data[i], ifconfig);

        if ((status != SIGAR_OK) ||
            (ifconfig->flags & SIGAR_IFF_LOOPBACK) ||
            !ifconfig->hwaddr.addr.in)   /* no mac address */
        {
            continue;
        }

        if (!possible_config.flags) {
            /* save for later for use if we're not connected to the net
             * or all interfaces are aliases (e.g. solaris zone)
             */
            memcpy(&possible_config, ifconfig, sizeof(*ifconfig));
        }
        if (!ifconfig->address.addr.in) {
            continue; /* no ip address */
        }
        if (strchr(iflist.data[i], ':')) {
            continue; /* alias */
        }

        found = 1;
        break;
    }

    sigar_net_interface_list_destroy(sigar, &iflist);

    if (found) {
        return SIGAR_OK;
    }
    else if (possible_config.flags) {
        memcpy(ifconfig, &possible_config, sizeof(*ifconfig));
        return SIGAR_OK;
    }
    else {
        return SIGAR_ENXIO;
    }
}

struct hostent *sigar_gethostbyname(const char *name,
                                    sigar_hostent_t *data)
{
    struct hostent *hp = NULL;

#if defined(__linux__)
    gethostbyname_r(name, &data->hs,
                    data->buffer, sizeof(data->buffer),
                    &hp, &data->error);
#elif defined(__sun)
    hp = gethostbyname_r(name, &data->hs,
                         data->buffer, sizeof(data->buffer),
                         &data->error);
#elif defined(SIGAR_HAS_HOSTENT_DATA)
    if (gethostbyname_r(name, &data->hs, &data->hd) == 0) {
        hp = &data->hs;
    }
    else {
        data->error = h_errno;
    }
#else
    hp = gethostbyname(name);
#endif

    return hp;
}
