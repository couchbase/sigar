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

#ifndef SIGAR_H
#define SIGAR_H

/* System Information Gatherer And Reporter */

#include <limits.h>
#include <sigar_visibility.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_LP64)         || \
    defined(__LP64__)      || \
    defined(__64BIT__)     || \
    defined(__powerpc64__) || \
    defined(__osf__)
#define SIGAR_64BIT
#endif

   typedef int32_t sigar_int32_t;
   typedef int64_t sigar_int64_t;
   typedef uint32_t sigar_uint32_t;
   typedef uint64_t sigar_uint64_t;

#define SIGAR_FIELD_NOTIMPL -1

#define SIGAR_OK 0
#define SIGAR_START_ERROR 20000
#define SIGAR_ENOTIMPL       (SIGAR_START_ERROR + 1)
#define SIGAR_OS_START_ERROR (SIGAR_START_ERROR*2)

#ifdef WIN32
#   define SIGAR_ENOENT ERROR_FILE_NOT_FOUND
#   define SIGAR_EACCES ERROR_ACCESS_DENIED
#   define SIGAR_ENXIO  ERROR_BAD_DRIVER_LEVEL
#else
#   define SIGAR_ENOENT ENOENT
#   define SIGAR_EACCES EACCES
#   define SIGAR_ENXIO  ENXIO
#endif

#define SIGAR_DECLARE(type) SIGAR_PUBLIC_API type

#if defined(PATH_MAX)
#   define SIGAR_PATH_MAX PATH_MAX
#elif defined(MAXPATHLEN)
#   define SIGAR_PATH_MAX MAXPATHLEN
#else
#   define SIGAR_PATH_MAX 4096
#endif

#ifdef WIN32
typedef sigar_uint64_t sigar_pid_t;
typedef unsigned long sigar_uid_t;
typedef unsigned long sigar_gid_t;
#else
#include <sys/types.h>
typedef pid_t sigar_pid_t;
typedef uid_t sigar_uid_t;
typedef gid_t sigar_gid_t;
#endif

typedef struct sigar_t sigar_t;

SIGAR_DECLARE(int) sigar_open(sigar_t **sigar);

SIGAR_DECLARE(int) sigar_close(sigar_t *sigar);

SIGAR_DECLARE(sigar_pid_t) sigar_pid_get(sigar_t *sigar);

SIGAR_DECLARE(char *) sigar_strerror(sigar_t *sigar, int err);

/* system memory info */

typedef struct {
    sigar_uint64_t
        ram,
        total,
        used,
        free,
        actual_used,
        actual_free;
    double used_percent;
    double free_percent;
} sigar_mem_t;

SIGAR_DECLARE(int) sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem);

typedef struct {
    sigar_uint64_t
        total,
        used,
        free,
        page_in,
        page_out,
        allocstall,             /* up until 4.10 */
        allocstall_dma,         /* 4.10 onwards */
        allocstall_dma32,       /* 4.10 onwards */
        allocstall_normal,      /* 4.10 onwards */
        allocstall_movable;     /* 4.10 onwards */
} sigar_swap_t;

SIGAR_DECLARE(int) sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap);

typedef struct {
    sigar_uint64_t
        user,
        sys,
        nice,
        idle,
        wait,
        irq,
        soft_irq,
        stolen,
        total;
} sigar_cpu_t;

SIGAR_DECLARE(int) sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu);

typedef struct {
    double uptime;
} sigar_uptime_t;

typedef struct {
    unsigned long number;
    unsigned long size;
    sigar_pid_t *data;
} sigar_proc_list_t;

SIGAR_DECLARE(int) sigar_proc_list_get(sigar_t *sigar,
                                       sigar_proc_list_t *proclist);

SIGAR_DECLARE(int)
sigar_proc_list_get_children(sigar_t* sigar,
                             sigar_pid_t ppid,
                             sigar_proc_list_t* proclist);

SIGAR_DECLARE(int) sigar_proc_list_destroy(sigar_t *sigar,
                                           sigar_proc_list_t *proclist);


typedef struct {
    sigar_uint64_t
        size,
        resident,
        share,
        minor_faults,
        major_faults,
        page_faults;
} sigar_proc_mem_t;

SIGAR_DECLARE(int) sigar_proc_mem_get(sigar_t *sigar, sigar_pid_t pid,
                                      sigar_proc_mem_t *procmem);

typedef struct {
    sigar_uint64_t
        start_time,
        user,
        sys,
        total;
} sigar_proc_time_t;

// Not used externally
int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                                       sigar_proc_time_t *proctime);

typedef struct {
    /* must match sigar_proc_time_t fields */
    sigar_uint64_t
        start_time,
        user,
        sys,
        total;
    sigar_uint64_t last_time;
    double percent;
} sigar_proc_cpu_t;

SIGAR_DECLARE(int) sigar_proc_cpu_get(sigar_t *sigar, sigar_pid_t pid,
                                      sigar_proc_cpu_t *proccpu);

#define SIGAR_PROC_STATE_SLEEP  'S'
#define SIGAR_PROC_STATE_RUN    'R'
#define SIGAR_PROC_STATE_STOP   'T'
#define SIGAR_PROC_STATE_ZOMBIE 'Z'
#define SIGAR_PROC_STATE_IDLE   'D'

#define SIGAR_PROC_NAME_LEN 128

typedef struct {
    char name[SIGAR_PROC_NAME_LEN];
    char state;
    sigar_pid_t ppid;
    int tty;
    int priority;
    int nice;
    int processor;
    sigar_uint64_t threads;
} sigar_proc_state_t;

SIGAR_DECLARE(int) sigar_proc_state_get(sigar_t *sigar, sigar_pid_t pid,
                                        sigar_proc_state_t *procstate);

typedef struct {
    unsigned long number;
    unsigned long size;
    char **data;
} sigar_proc_args_t;

typedef struct {
    void *data; /* user data */

    int (*module_getter)(void *, char *, int);
} sigar_proc_modules_t;


typedef enum {
    SIGAR_FSTYPE_UNKNOWN,
    SIGAR_FSTYPE_NONE,
    SIGAR_FSTYPE_LOCAL_DISK,
    SIGAR_FSTYPE_NETWORK,
    SIGAR_FSTYPE_RAM_DISK,
    SIGAR_FSTYPE_CDROM,
    SIGAR_FSTYPE_SWAP,
    SIGAR_FSTYPE_MAX
} sigar_file_system_type_e;

#define SIGAR_FS_NAME_LEN SIGAR_PATH_MAX
#define SIGAR_FS_INFO_LEN 256

typedef struct {
    char dir_name[SIGAR_FS_NAME_LEN];
    char dev_name[SIGAR_FS_NAME_LEN];
    char type_name[SIGAR_FS_INFO_LEN];     /* e.g. "local" */
    char sys_type_name[SIGAR_FS_INFO_LEN]; /* e.g. "ext3" */
    char options[SIGAR_FS_INFO_LEN];
    sigar_file_system_type_e type;
    unsigned long flags;
} sigar_file_system_t;

typedef struct {
    unsigned long number;
    unsigned long size;
    sigar_file_system_t *data;
} sigar_file_system_list_t;

SIGAR_DECLARE(int)
sigar_file_system_list_get(sigar_t *sigar,
                           sigar_file_system_list_t *fslist);

SIGAR_DECLARE(int)
sigar_file_system_list_destroy(sigar_t *sigar,
                               sigar_file_system_list_t *fslist);

#undef SIGAR_DISK_USAGE_T


typedef struct {
    enum {
        SIGAR_AF_UNSPEC,
        SIGAR_AF_INET,
        SIGAR_AF_INET6,
        SIGAR_AF_LINK
    } family;
    union {
        sigar_uint32_t in;
        sigar_uint32_t in6[4];
        unsigned char mac[8];
    } addr;
} sigar_net_address_t;

#define SIGAR_INET6_ADDRSTRLEN 46

/*
 * platforms define most of these "standard" flags,
 * but of course, with different values in some cases.
 */
#define SIGAR_IFF_UP          0x1
#define SIGAR_IFF_BROADCAST   0x2
#define SIGAR_IFF_DEBUG       0x4
#define SIGAR_IFF_LOOPBACK    0x8
#define SIGAR_IFF_POINTOPOINT 0x10
#define SIGAR_IFF_NOTRAILERS  0x20
#define SIGAR_IFF_RUNNING     0x40
#define SIGAR_IFF_NOARP       0x80
#define SIGAR_IFF_PROMISC     0x100
#define SIGAR_IFF_ALLMULTI    0x200
#define SIGAR_IFF_MULTICAST   0x800
#define SIGAR_IFF_SLAVE       0x1000
#define SIGAR_IFF_MASTER      0x2000
#define SIGAR_IFF_DYNAMIC     0x4000

#define SIGAR_NULL_HWADDR "00:00:00:00:00:00"

/* scope values from linux-2.6/include/net/ipv6.h */
#define SIGAR_IPV6_ADDR_ANY        0x0000
#define SIGAR_IPV6_ADDR_UNICAST    0x0001
#define SIGAR_IPV6_ADDR_MULTICAST  0x0002
#define SIGAR_IPV6_ADDR_LOOPBACK   0x0010
#define SIGAR_IPV6_ADDR_LINKLOCAL  0x0020
#define SIGAR_IPV6_ADDR_SITELOCAL  0x0040
#define SIGAR_IPV6_ADDR_COMPATv4   0x0080

typedef struct {
    char name[16];
    char type[64];
    char description[256];
    sigar_net_address_t hwaddr;
    sigar_net_address_t address;
    sigar_net_address_t destination;
    sigar_net_address_t broadcast;
    sigar_net_address_t netmask;
    sigar_net_address_t address6;
    int prefix6_length;
    int scope6;
    sigar_uint64_t
        flags,
        mtu,
        metric;
    int tx_queue_len;
} sigar_net_interface_config_t;

SIGAR_DECLARE(int)
sigar_net_interface_config_get(sigar_t *sigar,
                               const char *name,
                               sigar_net_interface_config_t *ifconfig);

SIGAR_DECLARE(int)
sigar_net_interface_config_primary_get(sigar_t *sigar,
                                       sigar_net_interface_config_t *ifconfig);


typedef struct {
    unsigned long number;
    unsigned long size;
    char **data;
} sigar_net_interface_list_t;

SIGAR_DECLARE(int)
sigar_net_interface_list_get(sigar_t *sigar,
                             sigar_net_interface_list_t *iflist);

SIGAR_DECLARE(int)
sigar_net_interface_list_destroy(sigar_t *sigar,
                                 sigar_net_interface_list_t *iflist);

#define SIGAR_NETCONN_CLIENT 0x01
#define SIGAR_NETCONN_SERVER 0x02

#define SIGAR_NETCONN_TCP  0x10
#define SIGAR_NETCONN_UDP  0x20
#define SIGAR_NETCONN_RAW  0x40
#define SIGAR_NETCONN_UNIX 0x80

enum {
    SIGAR_TCP_ESTABLISHED = 1,
    SIGAR_TCP_SYN_SENT,
    SIGAR_TCP_SYN_RECV,
    SIGAR_TCP_FIN_WAIT1,
    SIGAR_TCP_FIN_WAIT2,
    SIGAR_TCP_TIME_WAIT,
    SIGAR_TCP_CLOSE,
    SIGAR_TCP_CLOSE_WAIT,
    SIGAR_TCP_LAST_ACK,
    SIGAR_TCP_LISTEN,
    SIGAR_TCP_CLOSING,
    SIGAR_TCP_IDLE,
    SIGAR_TCP_BOUND,
    SIGAR_TCP_UNKNOWN
};

typedef struct {
    unsigned long local_port;
    sigar_net_address_t local_address;
    unsigned long remote_port;
    sigar_net_address_t remote_address;
    sigar_uid_t uid;
    unsigned long inode;
    int type;
    int state;
    unsigned long send_queue;
    unsigned long receive_queue;
} sigar_net_connection_t;

typedef struct {
    unsigned long number;
    unsigned long size;
    sigar_net_connection_t *data;
} sigar_net_connection_list_t;

SIGAR_DECLARE(int)
sigar_net_connection_list_get(sigar_t *sigar,
                              sigar_net_connection_list_t *connlist,
                              int flags);

SIGAR_DECLARE(int)
sigar_net_connection_list_destroy(sigar_t *sigar,
                                  sigar_net_connection_list_t *connlist);

typedef struct sigar_net_connection_walker_t sigar_net_connection_walker_t;

/* alternative to sigar_net_connection_list_get */
struct sigar_net_connection_walker_t {
    sigar_t *sigar;
    int flags;
    void *data; /* user data */
    int (*add_connection)(sigar_net_connection_walker_t *walker,
                          sigar_net_connection_t *connection);
};

SIGAR_DECLARE(int)
sigar_net_connection_walk(sigar_net_connection_walker_t *walker);

#ifdef __cplusplus
}
#endif

#endif
