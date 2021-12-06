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
#include <fcntl.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#include "sigar.h"
#include "sigar_private.h"
#include "sigar_util.h"
#include "sigar_os.h"

#define pageshift(x) ((x) << sigar->pagesize)

#define PROC_FS_ROOT "/proc/"
#define PROC_MEMINFO PROC_FS_ROOT "meminfo"
#define PROC_VMSTAT  PROC_FS_ROOT "vmstat"
#define PROC_STAT    PROC_FS_ROOT "stat"

#define PROC_PSTAT   "/stat"
#define PROC_PSTATUS "/status"

#define sigar_strtoul(ptr) strtoul(ptr, &ptr, 10)

#define sigar_strtoull(ptr) strtoull(ptr, &ptr, 10)

#define sigar_isspace(c) (isspace(((unsigned char)(c))))

#define sigar_isdigit(c) (isdigit(((unsigned char)(c))))

#define UITOA_BUFFER_SIZE (sizeof(int) * 3 + 1)

const char* mock_root = nullptr;

// To allow mocking around with the linux tests just add a prefix
SIGAR_PUBLIC_API void sigar_set_procfs_root(const char* root) {
    mock_root = root;
}

static char* sigar_uitoa(char* buf, unsigned int n, int* len) {
    char* start = buf + UITOA_BUFFER_SIZE - 1;

    *start = 0;

    do {
        *--start = '0' + (n % 10);
        ++*len;
        n /= 10;
    } while (n);

    return start;
}

static char* sigar_skip_token(char* p) {
    while (sigar_isspace(*p))
        p++;
    while (*p && !sigar_isspace(*p))
        p++;
    return p;
}

static char* sigar_proc_filename(char* buffer,
                                 int buflen,
                                 sigar_pid_t bigpid,
                                 const char* fname,
                                 int fname_len) {
    int len = 0;
    char* ptr = buffer;
    unsigned int pid = (unsigned int)bigpid; /* XXX -- This isn't correct */
    char pid_buf[UITOA_BUFFER_SIZE];
    char* pid_str = sigar_uitoa(pid_buf, pid, &len);

    assert((unsigned int)buflen >=
           (SSTRLEN(PROC_FS_ROOT) + UITOA_BUFFER_SIZE + fname_len + 1));

    memcpy(ptr, PROC_FS_ROOT, SSTRLEN(PROC_FS_ROOT));
    ptr += SSTRLEN(PROC_FS_ROOT);

    memcpy(ptr, pid_str, len);
    ptr += len;

    memcpy(ptr, fname, fname_len);
    ptr += fname_len;
    *ptr = '\0';

    return buffer;
}

static int sigar_file2str(const char* fname, char* buffer, int buflen) {
    int fd;
    if (mock_root) {
        char mock_name[BUFSIZ];
        const char* ptr = mock_name;
        snprintf(mock_name,
                 sizeof(mock_name),
                 "%s/mock/linux%s",
                 mock_root,
                 fname);
        fd = open(ptr, O_RDONLY);
    } else {
        fd = open(fname, O_RDONLY);
    }

    if (fd < 0) {
        return ENOENT;
    }

    int len, status;
    if ((len = read(fd, buffer, buflen - 1)) < 0) {
        status = errno;
    } else {
        status = SIGAR_OK;
        buffer[len] = '\0';
    }
    close(fd);

    return status;
}

static int sigar_proc_file2str(char* buffer,
                               int buflen,
                               sigar_pid_t pid,
                               const char* fname,
                               int fname_len) {
    int retval;

    buffer = sigar_proc_filename(buffer, buflen, pid, fname, fname_len);

    retval = sigar_file2str(buffer, buffer, buflen);

    if (retval != SIGAR_OK) {
        switch (retval) {
        case ENOENT:
            retval = ESRCH; /* no such process */
        default:
            break;
        }
    }

    return retval;
}

#define SIGAR_PROC_FILE2STR(buffer, pid, fname) \
    sigar_proc_file2str(buffer, sizeof(buffer), pid, fname, SSTRLEN(fname))

#define SIGAR_SKIP_SPACE(ptr)   \
    while (sigar_isspace(*ptr)) \
    ++ptr

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
        sigar->boot_time = time(nullptr);
    }

    return SIGAR_OK;
}

int sigar_os_open(sigar_t **sigar)
{
    int i, status;
    *sigar = static_cast<sigar_t*>(malloc(sizeof(sigar_t)));
    if (*sigar == nullptr) {
        return SIGAR_ENOMEM;
    }

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
    (*sigar)->last_proc_stat.pid = -1;

    return SIGAR_OK;
}

int sigar_os_close(sigar_t *sigar)
{
    free(sigar);
    return SIGAR_OK;
}

char *sigar_os_error_string(sigar_t *sigar, int err)
{
    return nullptr;
}

#define MEMINFO_PARAM(a) a ":", SSTRLEN(a ":")

static uint64_t sigar_meminfo(char* buffer, const char* attr, int len) {
    uint64_t val = 0;
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

static uint64_t sigar_vmstat(char* buffer, const char* attr) {
    uint64_t val = -1;
    char *ptr;

    if ((ptr = strstr(buffer, attr))) {
        ptr = sigar_skip_token(ptr);
        val = strtoull(ptr, nullptr, 10);
    }

    return val;
}

int sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem)
{
    uint64_t buffers, cached, kern;
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

    return SIGAR_OK;
}

int sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap)
{
    char buffer[BUFSIZ];

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

    if (status != SIGAR_OK) {
        return status;
    }

    swap->page_in = sigar_vmstat(buffer, "\npswpin");
    swap->page_out = sigar_vmstat(buffer, "\npswpout");

    swap->allocstall = sigar_vmstat(buffer, "\nallocstall");
    swap->allocstall_dma = sigar_vmstat(buffer, "\nallocstall_dma");
    swap->allocstall_dma32 = sigar_vmstat(buffer, "\nallocstall_dma32");
    swap->allocstall_normal = sigar_vmstat(buffer, "\nallocstall_normal");
    swap->allocstall_movable = sigar_vmstat(buffer, "\nallocstall_movable");

    return SIGAR_OK;
}

int sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    char buffer[BUFSIZ];
    int status = sigar_file2str(PROC_STAT, buffer, sizeof(buffer));

    if (status != SIGAR_OK) {
        return status;
    }

    // The first line in /proc/stat looks like:
    // cpu user nice system idle iowait irq softirq steal guest guest_nice
    // (The amount of time, measured in units of USER_HZ)
    char *ptr = sigar_skip_token(buffer);
    cpu->user = SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->nice = SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->sys = SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->idle = SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->wait = SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->irq = SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->soft_irq = SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->stolen = SIGAR_TICK2MSEC(sigar_strtoull(ptr));
    cpu->total = cpu->user + cpu->nice + cpu->sys + cpu->idle + cpu->wait +
                 cpu->irq + cpu->soft_irq + cpu->stolen;

    return SIGAR_OK;
}

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist)
{
    DIR* dirp = opendir(PROC_FS_ROOT);
    struct dirent *ent;

    if (!dirp) {
        return errno;
    }

    while ((ent = readdir(dirp)) != nullptr) {
        if (!sigar_isdigit(*ent->d_name)) {
            continue;
        }

        /* XXX: more sanity checking */

        SIGAR_PROC_LIST_GROW(proclist);

        proclist->data[proclist->number++] = strtoul(ent->d_name, nullptr, 10);
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

    time_t timenow = time(nullptr);

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

        if (sigar->last_proc_stat.ppid == uint64_t(ppid)) {
            return SIGAR_OK;
        }
        pid = sigar->last_proc_stat.ppid;
    } while (sigar->last_proc_stat.ppid != 0);
    return -1;
}

int sigar_os_proc_list_get_children(sigar_t* sigar,
                                    sigar_pid_t ppid,
                                    sigar_proc_list_t* proclist) {
    DIR* dirp = opendir(PROC_FS_ROOT);
    struct dirent* ent;

    if (!dirp) {
        return errno;
    }

    while ((ent = readdir(dirp)) != nullptr) {
        if (!sigar_isdigit(*ent->d_name)) {
            continue;
        }

        /* XXX: more sanity checking */
        sigar_pid_t pid = strtoul(ent->d_name, nullptr, 10);
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
    ptr = sigar_skip_token(ptr);
    procstate->threads = sigar_strtoul(ptr);

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
