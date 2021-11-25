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

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include "sigar.h"
#include "sigar_private.h"
#include "sigar_util.h"
#include "sigar_os.h"

#define pageshift(x) ((x) << sigar->pagesize)

#define PROC_MEMINFO PROC_FS_ROOT "meminfo"
#define PROC_VMSTAT  PROC_FS_ROOT "vmstat"
#define PROC_MTRR    PROC_FS_ROOT "mtrr"
#define PROC_STAT    PROC_FS_ROOT "stat"

#define PROC_PSTAT   "/stat"
#define PROC_PSTATUS "/status"

/*
 * /proc/self/stat fields:
 * 1 - pid
 * 2 - comm
 * 3 - state
 * 4 - ppid
 * 5 - pgrp
 * 6 - session
 * 7 - tty_nr
 * 8 - tpgid
 * 9 - flags
 * 10 - minflt
 * 11 - cminflt
 * 12 - majflt
 * 13 - cmajflt
 * 14 - utime
 * 15 - stime
 * 16 - cutime
 * 17 - cstime
 * 18 - priority
 * 19 - nice
 * 20 - 0 (removed field)
 * 21 - itrealvalue
 * 22 - starttime
 * 23 - vsize
 * 24 - rss
 * 25 - rlim
 * 26 - startcode
 * 27 - endcode
 * 28 - startstack
 * 29 - kstkesp
 * 30 - kstkeip
 * 31 - signal
 * 32 - blocked
 * 33 - sigignore
 * 34 - sigcache
 * 35 - wchan
 * 36 - nswap
 * 37 - cnswap
 * 38 - exit_signal <-- looking for this.
 * 39 - processor
 * ... more for newer RH
 */

#define PROC_SIGNAL_IX 38

static int get_proc_signal_offset(void)
{
    char buffer[BUFSIZ], *ptr=buffer;
    int fields = 0;
    int status = sigar_file2str(PROCP_FS_ROOT "self/stat",
                                buffer, sizeof(buffer));

    if (status != SIGAR_OK) {
        return 1;
    }

    while (*ptr) {
        if (*ptr++ == ' ') {
            fields++;
        }
    }

    return (fields - PROC_SIGNAL_IX) + 1;
}

static int sigar_boot_time_get(sigar_t *sigar)
{
    FILE *fp;
    char buffer[BUFSIZ], *ptr;
    int found = 0;

    if (!(fp = fopen(PROC_STAT, "r"))) {
        return errno;
    }

    while ((ptr = fgets(buffer, sizeof(buffer), fp))) {
        if (strnEQ(ptr, "btime", 5)) {
            if ((ptr = sigar_skip_token(ptr))) {
                sigar->boot_time = sigar_strtoul(ptr);
                found = 1;
            }
            break;
        }
    }

    fclose(fp);

    if (!found) {
        /* should never happen */
        sigar->boot_time = time(NULL);
    }

    return SIGAR_OK;
}

int sigar_os_open(sigar_t **sigar)
{
    int i, status;
    int kernel_rev, has_nptl;
    struct utsname name;

    *sigar = malloc(sizeof(**sigar));

    (*sigar)->pagesize = 0;
    i = getpagesize();
    while ((i >>= 1) > 0) {
        (*sigar)->pagesize++;
    }

    status = sigar_boot_time_get(*sigar);
    if (status != SIGAR_OK) {
        return status;
    }

    (*sigar)->ticks = sysconf(_SC_CLK_TCK);
    (*sigar)->ram = -1;
    (*sigar)->proc_signal_offset = -1;
    (*sigar)->last_proc_stat.pid = -1;

    uname(&name);
    /* 2.X.y.z -> just need X (unless there is ever a kernel version 3!) */
    kernel_rev = atoi(&name.release[2]);
    if (kernel_rev >= 6) {
        has_nptl = 1;
    }
    else {
        has_nptl = getenv("SIGAR_HAS_NPTL") ? 1 : 0;
    }
    (*sigar)->has_nptl = has_nptl;

    return SIGAR_OK;
}

int sigar_os_close(sigar_t *sigar)
{
    free(sigar);
    return SIGAR_OK;
}

char *sigar_os_error_string(sigar_t *sigar, int err)
{
    return NULL;
}

static int get_ram(sigar_t *sigar, sigar_mem_t *mem)
{
    char buffer[BUFSIZ], *ptr;
    FILE *fp;
    int total = 0;
    sigar_uint64_t sys_total = (mem->total / (1024 * 1024));

    if (sigar->ram > 0) {
        /* return cached value */
        mem->ram = sigar->ram;
        return SIGAR_OK;
    }

    if (sigar->ram == 0) {
        return ENOENT;
    }

    /*
     * Memory Type Range Registers
     * write-back registers add up to the total.
     * Well, they are supposed to add up, but seen
     * at least one configuration where that is not the
     * case.
     */
    if (!(fp = fopen(PROC_MTRR, "r"))) {
        return errno;
    }

    while ((ptr = fgets(buffer, sizeof(buffer), fp))) {
        if (!(ptr = strstr(ptr, "size="))) {
            continue;
        }

        if (!strstr(ptr, "write-back")) {
            continue;
        }

        ptr += 5;
        while (sigar_isspace(*ptr)) {
            ++ptr;
        }

        total += atoi(ptr);
    }

    fclose(fp);

    if ((total - sys_total) > 256) {
        /* mtrr write-back registers are way off
         * kernel should not be using more that 256MB of mem
         */
        total = 0; /* punt */
    }

    if (total == 0) {
        return ENOENT;
    }

    mem->ram = sigar->ram = total;

    return SIGAR_OK;
}

#define MEMINFO_PARAM(a) a ":", SSTRLEN(a ":")

static  sigar_uint64_t sigar_meminfo(char *buffer,
                                                 char *attr, int len)
{
    sigar_uint64_t val = 0;
    char *ptr, *tok;

    if ((ptr = strstr(buffer, attr))) {
        ptr += len;
        val = strtoull(ptr, &tok, 0);
        while (*tok == ' ') {
            ++tok;
        }
        if (*tok == 'k') {
            val *= 1024;
        }
        else if (*tok == 'M') {
            val *= (1024 * 1024);
        }
    }

    return val;
}

static  sigar_uint64_t sigar_vmstat(char *buffer, char *attr)
{
    sigar_uint64_t val = -1;
    char *ptr;

    if ((ptr = strstr(buffer, attr))) {
        ptr = sigar_skip_token(ptr);
        val = strtoull(ptr, NULL, 10);
    }

    return val;
}

int sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem)
{
    sigar_uint64_t buffers, cached, kern;
    char buffer[BUFSIZ];

    int status = sigar_file2str(PROC_MEMINFO,
                                buffer, sizeof(buffer));

    if (status != SIGAR_OK) {
        return status;
    }

    mem->total  = sigar_meminfo(buffer, MEMINFO_PARAM("MemTotal"));
    mem->free   = sigar_meminfo(buffer, MEMINFO_PARAM("MemFree"));
    mem->used   = mem->total - mem->free;

    buffers = sigar_meminfo(buffer, MEMINFO_PARAM("Buffers"));
    cached  = sigar_meminfo(buffer, MEMINFO_PARAM("Cached"));

    kern = buffers + cached;
    mem->actual_free = mem->free + kern;
    mem->actual_used = mem->used - kern;

    sigar_mem_calc_ram(sigar, mem);

    if (get_ram(sigar, mem) != SIGAR_OK) {
        /* XXX other options on failure? */
    }

    return SIGAR_OK;
}

int sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap)
{
    char buffer[BUFSIZ], *ptr;

    /* XXX: we open/parse the same file here as sigar_mem_get */
    int status = sigar_file2str(PROC_MEMINFO,
                                buffer, sizeof(buffer));

    if (status != SIGAR_OK) {
        return status;
    }

    swap->total  = sigar_meminfo(buffer, MEMINFO_PARAM("SwapTotal"));
    swap->free   = sigar_meminfo(buffer, MEMINFO_PARAM("SwapFree"));
    swap->used   = swap->total - swap->free;

    swap->page_in = swap->page_out = -1;

    swap->allocstall = -1;
    swap->allocstall_dma = -1;
    swap->allocstall_dma32 = -1;
    swap->allocstall_normal = -1;
    swap->allocstall_movable = -1;

    status = sigar_file2str(PROC_VMSTAT,
                            buffer, sizeof(buffer));

    if (status == SIGAR_OK) {
        /* 2.6+ kernel */
        swap->page_in = sigar_vmstat(buffer, "\npswpin");
        swap->page_out = sigar_vmstat(buffer, "\npswpout");

        swap->allocstall = sigar_vmstat(buffer, "\nallocstall");
        swap->allocstall_dma = sigar_vmstat(buffer, "\nallocstall_dma");
        swap->allocstall_dma32 = sigar_vmstat(buffer, "\nallocstall_dma32");
        swap->allocstall_normal = sigar_vmstat(buffer, "\nallocstall_normal");
        swap->allocstall_movable = sigar_vmstat(buffer, "\nallocstall_movable");
    }
    else {
        /* 2.2, 2.4 kernels */
        status = sigar_file2str(PROC_STAT,
                                buffer, sizeof(buffer));
        if (status != SIGAR_OK) {
            return status;
        }

        if ((ptr = strstr(buffer, "\nswap"))) {
            ptr = sigar_skip_token(ptr);
            swap->page_in = sigar_strtoull(ptr);
            swap->page_out = sigar_strtoull(ptr);
        }
    }

    return SIGAR_OK;
}

static void get_cpu_metrics(sigar_t *sigar, sigar_cpu_t *cpu, char *line)
{
    char *ptr = sigar_skip_token(line); /* "cpu%d" */

    cpu->user += SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->nice += SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->sys  += SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->idle += SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    if (*ptr == ' ') {
        /* 2.6+ kernels only */
        cpu->wait += SIGAR_TICK2MSEC(sigar_strtoull(ptr));
        cpu->irq += SIGAR_TICK2MSEC(sigar_strtoull(ptr));
        cpu->soft_irq += SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    }
    if (*ptr == ' ') {
        /* 2.6.11+ kernels only */
        cpu->stolen += SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    }
    cpu->total =
        cpu->user + cpu->nice + cpu->sys + cpu->idle +
        cpu->wait + cpu->irq + cpu->soft_irq + cpu->stolen;
}

int sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    char buffer[BUFSIZ];
    int status = sigar_file2str(PROC_STAT, buffer, sizeof(buffer));

    if (status != SIGAR_OK) {
        return status;
    }

    SIGAR_ZERO(cpu);
    get_cpu_metrics(sigar, cpu, buffer);

    return SIGAR_OK;
}

/*
 * seems the easiest/fastest way to tell if a process listed in /proc
 * is a thread is to check the "exit signal" flag in /proc/num/stat.
 * any value other than SIGCHLD seems to be a thread.  this make hulk mad.
 * redhat's procps patch (named "threadbadhack.pat") does not use
 * this flag to filter out threads.  instead does much more expensive
 * comparisions.  their patch also bubbles up thread cpu times to the main
 * process.  functionality we currently lack.
 * when nptl is in use, this is not the case and all threads spawned from
 * a process have the same pid.  however, it seems both old-style linux
 * threads and nptl threads can be run on the same machine.
 * there is also the "Tgid" field in /proc/self/status which could be used
 * to detect threads, but this is not available in older kernels.
 */
static  int proc_isthread(sigar_t *sigar, char *pidstr, int len)
{
    char buffer[BUFSIZ], *ptr=buffer;
    int fd, n, offset=sigar->proc_signal_offset;

    /* sprintf(buffer, "/proc/%s/stat", pidstr) */
    memcpy(ptr, PROCP_FS_ROOT, SSTRLEN(PROCP_FS_ROOT));
    ptr += SSTRLEN(PROCP_FS_ROOT);

    memcpy(ptr, pidstr, len);
    ptr += len;

    memcpy(ptr, PROC_PSTAT, SSTRLEN(PROC_PSTAT));
    ptr += SSTRLEN(PROC_PSTAT);

    *ptr = '\0';

    if ((fd = open(buffer, O_RDONLY)) < 0) {
        /* unlikely if pid was from readdir proc */
        return 0;
    }

    n = read(fd, buffer, sizeof(buffer));
    close(fd);

    if (n < 0) {
        return 0; /* chances: slim..none */
    }

    buffer[n--] = '\0';

    /* exit_signal is the second to last field so we look backwards.
     * XXX if newer kernels drop more turds in this file we'll need
     * to go the other way.  luckily linux has no real api for this shit.
     */

    /* skip trailing crap */
    while ((n > 0) && !isdigit(buffer[n--])) ;

    while (offset-- > 0) {
        /* skip last field */
        while ((n > 0) && isdigit(buffer[n--])) ;

        /* skip whitespace */
        while ((n > 0) && !isdigit(buffer[n--])) ;
    }

    if (n < 3) {
        return 0; /* hulk smashed /proc? */
    }

    ptr = &buffer[n];
    /*
     * '17' == SIGCHLD == real process.
     * '33' and '0' are threads
     */
    if ((*ptr++ == '1') &&
        (*ptr++ == '7') &&
        (*ptr++ == ' '))
    {
        return 0;
    }

    return 1;
}

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist)
{
    DIR *dirp = opendir(PROCP_FS_ROOT);
    struct dirent *ent;
    register const int threadbadhack = !sigar->has_nptl;

    if (!dirp) {
        return errno;
    }

    if (threadbadhack && (sigar->proc_signal_offset == -1)) {
        sigar->proc_signal_offset = get_proc_signal_offset();
    }

    while ((ent = readdir(dirp)) != NULL) {
        if (!sigar_isdigit(*ent->d_name)) {
            continue;
        }

        if (threadbadhack &&
            proc_isthread(sigar, ent->d_name, strlen(ent->d_name)))
        {
            continue;
        }

        /* XXX: more sanity checking */

        SIGAR_PROC_LIST_GROW(proclist);

        proclist->data[proclist->number++] =
            strtoul(ent->d_name, NULL, 10);
    }

    closedir(dirp);

    return SIGAR_OK;
}

static int proc_stat_read(sigar_t *sigar, sigar_pid_t pid)
{
    char buffer[BUFSIZ], *ptr=buffer, *tmp;
    unsigned int len;
    linux_proc_stat_t *pstat = &sigar->last_proc_stat;
    int status;

    time_t timenow = time(NULL);

    /*
     * short-lived cache read/parse of last /proc/pid/stat
     * as this info is spread out across a few functions.
     */
    if (pstat->pid == pid) {
        if ((timenow - pstat->mtime) < SIGAR_LAST_PROC_EXPIRE) {
            return SIGAR_OK;
        }
    }

    pstat->pid = pid;
    pstat->mtime = timenow;

    status = SIGAR_PROC_FILE2STR(buffer, pid, PROC_PSTAT);

    if (status != SIGAR_OK) {
        return status;
    }

    if (!(ptr = strchr(ptr, '('))) {
        return EINVAL;
    }
    if (!(tmp = strrchr(++ptr, ')'))) {
        return EINVAL;
    }
    len = tmp-ptr;

    if (len >= sizeof(pstat->name)) {
        len = sizeof(pstat->name)-1;
    }

    /* (1,2) */
    memcpy(pstat->name, ptr, len);
    pstat->name[len] = '\0';
    ptr = tmp+1;

    SIGAR_SKIP_SPACE(ptr);
    pstat->state = *ptr++; /* (3) */
    SIGAR_SKIP_SPACE(ptr);

    pstat->ppid = sigar_strtoul(ptr); /* (4) */
    ptr = sigar_skip_token(ptr); /* (5) pgrp */
    ptr = sigar_skip_token(ptr); /* (6) session */
    pstat->tty = sigar_strtoul(ptr); /* (7) */
    ptr = sigar_skip_token(ptr); /* (8) tty pgrp */

    ptr = sigar_skip_token(ptr); /* (9) flags */
    pstat->minor_faults = sigar_strtoull(ptr); /* (10) */
    ptr = sigar_skip_token(ptr); /* (11) cmin flt */
    pstat->major_faults = sigar_strtoull(ptr); /* (12) */
    ptr = sigar_skip_token(ptr); /* (13) cmaj flt */

    pstat->utime = SIGAR_TICK2MSEC(sigar_strtoull(ptr)); /* (14) */
    pstat->stime = SIGAR_TICK2MSEC(sigar_strtoull(ptr)); /* (15) */

    ptr = sigar_skip_token(ptr); /* (16) cutime */
    ptr = sigar_skip_token(ptr); /* (17) cstime */

    pstat->priority = sigar_strtoul(ptr); /* (18) */
    pstat->nice     = sigar_strtoul(ptr); /* (19) */

    ptr = sigar_skip_token(ptr); /* (20) timeout */
    ptr = sigar_skip_token(ptr); /* (21) it_real_value */

    pstat->start_time  = sigar_strtoul(ptr); /* (22) */
    pstat->start_time /= sigar->ticks;
    pstat->start_time += sigar->boot_time; /* seconds */
    pstat->start_time *= 1000; /* milliseconds */

    pstat->vsize = sigar_strtoull(ptr); /* (23) */
    pstat->rss   = pageshift(sigar_strtoull(ptr)); /* (24) */

    ptr = sigar_skip_token(ptr); /* (25) rlim */
    ptr = sigar_skip_token(ptr); /* (26) startcode */
    ptr = sigar_skip_token(ptr); /* (27) endcode */
    ptr = sigar_skip_token(ptr); /* (28) startstack */
    ptr = sigar_skip_token(ptr); /* (29) kstkesp */
    ptr = sigar_skip_token(ptr); /* (30) kstkeip */
    ptr = sigar_skip_token(ptr); /* (31) signal */
    ptr = sigar_skip_token(ptr); /* (32) blocked */
    ptr = sigar_skip_token(ptr); /* (33) sigignore */
    ptr = sigar_skip_token(ptr); /* (34) sigcache */
    ptr = sigar_skip_token(ptr); /* (35) wchan */
    ptr = sigar_skip_token(ptr); /* (36) nswap */
    ptr = sigar_skip_token(ptr); /* (37) cnswap */
    ptr = sigar_skip_token(ptr); /* (38) exit_signal */

    pstat->processor = sigar_strtoul(ptr); /* (39) */

    return SIGAR_OK;
}

static int sigar_os_check_parents(sigar_t* sigar, pid_t pid, pid_t ppid) {
    do {
        if (proc_stat_read(sigar, pid) != SIGAR_OK) {
            return -1;
        }

        if (sigar->last_proc_stat.ppid == ppid) {
            return SIGAR_OK;
        }
        pid = sigar->last_proc_stat.ppid;
    } while (sigar->last_proc_stat.ppid != 0);
    return -1;
}

int sigar_os_proc_list_get_children(sigar_t* sigar,
                                    sigar_pid_t ppid,
                                    sigar_proc_list_t* proclist) {
    DIR* dirp = opendir(PROCP_FS_ROOT);
    struct dirent* ent;
    register const int threadbadhack = !sigar->has_nptl;

    if (!dirp) {
        return errno;
    }

    if (threadbadhack && (sigar->proc_signal_offset == -1)) {
        sigar->proc_signal_offset = get_proc_signal_offset();
    }

    while ((ent = readdir(dirp)) != NULL) {
        if (!sigar_isdigit(*ent->d_name)) {
            continue;
        }

        if (threadbadhack &&
            proc_isthread(sigar, ent->d_name, strlen(ent->d_name))) {
            continue;
        }

        /* XXX: more sanity checking */
        sigar_pid_t pid = strtoul(ent->d_name, NULL, 10);
        if (sigar_os_check_parents(sigar, pid, ppid) == SIGAR_OK) {
            SIGAR_PROC_LIST_GROW(proclist);
            proclist->data[proclist->number++] = pid;
        }
    }

    closedir(dirp);
    return SIGAR_OK;
}

int sigar_proc_mem_get(sigar_t *sigar, sigar_pid_t pid,
                       sigar_proc_mem_t *procmem)
{
    char buffer[BUFSIZ], *ptr=buffer;
    int status = proc_stat_read(sigar, pid);
    linux_proc_stat_t *pstat = &sigar->last_proc_stat;

    procmem->minor_faults = pstat->minor_faults;
    procmem->major_faults = pstat->major_faults;
    procmem->page_faults =
        procmem->minor_faults + procmem->major_faults;

    status = SIGAR_PROC_FILE2STR(buffer, pid, "/statm");

    if (status != SIGAR_OK) {
        return status;
    }

    procmem->size     = pageshift(sigar_strtoull(ptr));
    procmem->resident = pageshift(sigar_strtoull(ptr));
    procmem->share    = pageshift(sigar_strtoull(ptr));

    return SIGAR_OK;
}

int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_time_t *proctime)
{
    int status = proc_stat_read(sigar, pid);
    linux_proc_stat_t *pstat = &sigar->last_proc_stat;

    if (status != SIGAR_OK) {
        return status;
    }

    proctime->user = pstat->utime;
    proctime->sys  = pstat->stime;
    proctime->total = proctime->user + proctime->sys;
    proctime->start_time = pstat->start_time;

    return SIGAR_OK;
}

static int proc_status_get(sigar_t *sigar, sigar_pid_t pid,
                           sigar_proc_state_t *procstate)
{
    char buffer[BUFSIZ], *ptr;
    int status = SIGAR_PROC_FILE2STR(buffer, pid, PROC_PSTATUS);

    if (status != SIGAR_OK) {
        return status;
    }

    ptr = strstr(buffer, "\nThreads:");
    if (ptr) {
        /* 2.6+ kernel only */
        ptr = sigar_skip_token(ptr);
        procstate->threads = sigar_strtoul(ptr);
    }
    else {
        procstate->threads = SIGAR_FIELD_NOTIMPL;
    }

    return SIGAR_OK;
}

int sigar_proc_state_get(sigar_t *sigar, sigar_pid_t pid,
                         sigar_proc_state_t *procstate)
{
    int status = proc_stat_read(sigar, pid);
    linux_proc_stat_t *pstat = &sigar->last_proc_stat;

    if (status != SIGAR_OK) {
        return status;
    }

    memcpy(procstate->name, pstat->name, sizeof(procstate->name));
    procstate->state = pstat->state;

    procstate->ppid     = pstat->ppid;
    procstate->tty      = pstat->tty;
    procstate->priority = pstat->priority;
    procstate->nice     = pstat->nice;
    procstate->processor = pstat->processor;

    proc_status_get(sigar, pid, procstate);

    return SIGAR_OK;
}
