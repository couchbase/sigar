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

// The linux implementation consumes the files in the /proc filesystem per
// the documented format in https://man7.org/linux/man-pages/man5/proc.5.html

#include <boost/filesystem/path.hpp>
#include <dirent.h>
#include <fcntl.h>
#include <platform/dirutils.h>
#include <cassert>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <functional>

#include "sigar.h"
#include "sigar_private.h"

#define pageshift(x) ((x)*SystemConstants::instance().pagesize)
#define SIGAR_TICK2MSEC(s) \
    ((uint64_t)(s) *       \
     ((uint64_t)SIGAR_MSEC / (double)SystemConstants::instance().ticks))
#define SSTRLEN(s) (sizeof(s) - 1)

#define PROC_FS_ROOT "/proc/"
#define PROC_STAT PROC_FS_ROOT "stat"

#define PROC_PSTAT "/stat"

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

void sigar_tokenize_file_line_by_line(
        sigar_pid_t pid,
        const char* filename,
        std::function<bool(const std::vector<std::string_view>&)> callback,
        char delim = ' ') {
    boost::filesystem::path name;
    if (mock_root) {
        name = boost::filesystem::path{mock_root} / "mock" / "linux" / "proc";
    } else {
        name = boost::filesystem::path{"/proc"};
    }

    if (pid) {
        name = name / std::to_string(pid);
    }

    name = name / filename;
    cb::io::tokenizeFileLineByLine(name, callback, delim, false);
}

struct linux_proc_stat_t {
    sigar_pid_t pid;
    uint64_t vsize;
    uint64_t rss;
    uint64_t minor_faults;
    uint64_t major_faults;
    uint64_t ppid;
    int tty;
    int priority;
    int nice;
    uint64_t start_time;
    uint64_t utime;
    uint64_t stime;
    char name[SIGAR_PROC_NAME_LEN];
    char state;
    int processor;
};

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

struct SystemConstants {
    static SystemConstants instance() {
        static SystemConstants inst;
        return inst;
    }

    SystemConstants()
        : pagesize(getpagesize()),
          boot_time(get_boot_time()),
          ticks(sysconf(_SC_CLK_TCK)) {
    }
    static uint64_t get_boot_time() {
        uint64_t ret = 0;
        sigar_tokenize_file_line_by_line(
                0,
                "stat",
                [&ret](const auto& vec) {
                    if (vec.size() > 1 && vec.front() == "btime") {
                        ret = std::stoull(std::string(vec[1]));
                        return false;
                    }
                    return true;
                },
                ' ');
        return ret;
    }

    const int pagesize;
    const long boot_time;
    const int ticks;
};

class LinuxSigar : public sigar_t {
public:
    int get_memory(sigar_mem_t& mem) override;
    int get_swap(sigar_swap_t& swap) override;
    int get_cpu(sigar_cpu_t& cpu) override;
    int get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem) override;
    int get_proc_state(sigar_pid_t pid, sigar_proc_state_t& procstate) override;
    void iterate_child_processes(
            sigar_pid_t pid,
            sigar::IterateChildProcessCallback callback) override;

protected:
    int get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime) override;

    static bool check_parents(
            pid_t pid,
            pid_t ppid,
            const std::unordered_map<sigar_pid_t, linux_proc_stat_t>& procs);
    static std::pair<int, linux_proc_stat_t> proc_stat_read(sigar_pid_t pid);
};

sigar_t::sigar_t() = default;

sigar_t* sigar_t::New() {
    return new LinuxSigar;
}

static uint64_t stoull(std::string_view value) {
    auto pos = value.find_first_not_of(' ');
    if (pos != std::string_view::npos) {
        value.remove_prefix(pos);
    }

    uint64_t ret;
    auto [ptr, ec] = std::from_chars(value.begin(), value.end(), ret);
    if (ec == std::errc()) {
        if (ptr < value.end()) {
            while (*ptr == ' ') {
                ++ptr;
            }
            switch (*ptr) {
            case 'k':
                return ret * 1024;
            case 'M':
                return ret * 1024 * 1024;
            }
        }

        return ret;
    }
    return -1;
}

int LinuxSigar::get_memory(sigar_mem_t& mem) {
    uint64_t buffers = 0;
    uint64_t cached = 0;
    sigar_tokenize_file_line_by_line(
            0,
            "meminfo",
            [&mem, &buffers, &cached](const auto& vec) {
                if (vec.size() < 2) {
                    return true;
                }
                if (vec.front() == "MemTotal") {
                    mem.total = stoull(vec[1]);
                    return true;
                }
                if (vec.front() == "MemFree") {
                    mem.free = stoull(vec[1]);
                    return true;
                }
                if (vec.front() == "Buffers") {
                    buffers = stoull(vec[1]);
                    return true;
                }
                if (vec.front() == "Cached") {
                    cached = stoull(vec[1]);
                    return true;
                }

                return true;
            },
            ':');

    mem.used = mem.total - mem.free;
    auto kern = buffers + cached;
    mem.actual_free = mem.free + kern;
    mem.actual_used = mem.used - kern;
    mem_calc_ram(mem);

    return SIGAR_OK;
}

int LinuxSigar::get_swap(sigar_swap_t& swap) {
    sigar_tokenize_file_line_by_line(
            0,
            "meminfo",
            [&swap](const auto& vec) {
                if (vec.size() < 2) {
                    return true;
                }
                if (vec.front() == "SwapTotal") {
                    swap.total = stoull(vec[1]);
                    return true;
                }
                if (vec.front() == "SwapFree") {
                    swap.free = stoull(vec[1]);
                    return true;
                }
                return true;
            },
            ':');

    swap.used = swap.total - swap.free;
    sigar_tokenize_file_line_by_line(
            0,
            "vmstat",
            [&swap](const auto& vec) {
                if (vec.size() < 2) {
                    return true;
                }

                if (vec.front() == "pswpin") {
                    swap.page_in = stoull(vec[1]);
                } else if (vec.front() == "pswpout") {
                    swap.page_out = stoull(vec[1]);
                } else if (vec.front() == "allocstall") {
                    swap.allocstall = stoull(vec[1]);
                } else if (vec.front() == "allocstall_dma") {
                    swap.allocstall_dma = stoull(vec[1]);
                } else if (vec.front() == "allocstall_dma32") {
                    swap.allocstall_dma32 = stoull(vec[1]);
                } else if (vec.front() == "allocstall_normal") {
                    swap.allocstall_normal = stoull(vec[1]);
                } else if (vec.front() == "allocstall_movable") {
                    swap.allocstall_movable = stoull(vec[1]);
                }

                return true;
            },
            ' ');

    return SIGAR_OK;
}

int LinuxSigar::get_cpu(sigar_cpu_t& cpu) {
    int status = ENOENT;
    sigar_tokenize_file_line_by_line(
            0,
            "stat",
            [&cpu, &status, sigar = this](const auto& vec) {
                // The first line in /proc/stat looks like:
                // cpu user nice system idle iowait irq softirq steal guest
                // guest_nice (The amount of time, measured in units of
                // USER_HZ)
                if (vec.size() < 11) {
                    status = EINVAL;
                    return false;
                }
                if (vec.front() == "cpu") {
                    if (vec.size() < 9) {
                        status = EINVAL;
                        return false;
                    }

                    cpu.user = SIGAR_TICK2MSEC(stoull(vec[1]));
                    cpu.nice = SIGAR_TICK2MSEC(stoull(vec[2]));
                    cpu.sys = SIGAR_TICK2MSEC(stoull(vec[3]));
                    cpu.idle = SIGAR_TICK2MSEC(stoull(vec[4]));
                    cpu.wait = SIGAR_TICK2MSEC(stoull(vec[5]));
                    cpu.irq = SIGAR_TICK2MSEC(stoull(vec[6]));
                    cpu.soft_irq = SIGAR_TICK2MSEC(stoull(vec[7]));
                    cpu.stolen = SIGAR_TICK2MSEC(stoull(vec[8]));
                    cpu.total = cpu.user + cpu.nice + cpu.sys + cpu.idle +
                                cpu.wait + cpu.irq + cpu.soft_irq + cpu.stolen;
                    status = SIGAR_OK;
                    return false;
                }

                return true;
            },
            ' ');

    return status;
}

std::pair<int, linux_proc_stat_t> LinuxSigar::proc_stat_read(sigar_pid_t pid) {
    char buffer[BUFSIZ], *ptr = buffer, *tmp;
    unsigned int len;
    linux_proc_stat_t pstat = {};
    pstat.pid = pid;

    int status = SIGAR_PROC_FILE2STR(buffer, pid, PROC_PSTAT);

    if (status != SIGAR_OK) {
        return {status, {}};
    }

    if (!(ptr = strchr(ptr, '('))) {
        return {EINVAL, {}};
    }
    if (!(tmp = strrchr(++ptr, ')'))) {
        return {EINVAL, {}};
    }
    len = tmp - ptr;

    if (len >= sizeof(pstat.name)) {
        len = sizeof(pstat.name) - 1;
    }

    /* (1,2) */
    memcpy(pstat.name, ptr, len);
    pstat.name[len] = '\0';
    ptr = tmp + 1;

    SIGAR_SKIP_SPACE(ptr);
    pstat.state = *ptr++; /* (3) */
    SIGAR_SKIP_SPACE(ptr);

    pstat.ppid = sigar_strtoul(ptr); /* (4) */
    ptr = sigar_skip_token(ptr); /* (5) pgrp */
    ptr = sigar_skip_token(ptr); /* (6) session */
    pstat.tty = sigar_strtoul(ptr); /* (7) */
    ptr = sigar_skip_token(ptr); /* (8) tty pgrp */

    ptr = sigar_skip_token(ptr); /* (9) flags */
    pstat.minor_faults = sigar_strtoull(ptr); /* (10) */
    ptr = sigar_skip_token(ptr); /* (11) cmin flt */
    pstat.major_faults = sigar_strtoull(ptr); /* (12) */
    ptr = sigar_skip_token(ptr); /* (13) cmaj flt */

    pstat.utime = SIGAR_TICK2MSEC(sigar_strtoull(ptr)); /* (14) */
    pstat.stime = SIGAR_TICK2MSEC(sigar_strtoull(ptr)); /* (15) */

    ptr = sigar_skip_token(ptr); /* (16) cutime */
    ptr = sigar_skip_token(ptr); /* (17) cstime */

    pstat.priority = sigar_strtoul(ptr); /* (18) */
    pstat.nice = sigar_strtoul(ptr); /* (19) */

    ptr = sigar_skip_token(ptr); /* (20) timeout */
    ptr = sigar_skip_token(ptr); /* (21) it_real_value */

    pstat.start_time = sigar_strtoul(ptr); /* (22) */
    pstat.start_time /= SystemConstants::instance().ticks;
    pstat.start_time += SystemConstants::instance().boot_time; /* seconds */
    pstat.start_time *= 1000; /* milliseconds */

    pstat.vsize = sigar_strtoull(ptr); /* (23) */
    pstat.rss = pageshift(sigar_strtoull(ptr)); /* (24) */

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

    pstat.processor = sigar_strtoul(ptr); /* (39) */

    return {SIGAR_OK, pstat};
}

bool LinuxSigar::check_parents(
        pid_t pid,
        pid_t ppid,
        const std::unordered_map<sigar_pid_t, linux_proc_stat_t>& procs) {
    do {
        auto iter = procs.find(pid);
        if (iter == procs.end()) {
            return false;
        }

        if (iter->second.ppid == uint64_t(ppid)) {
            return true;
        }
        pid = iter->second.ppid;
    } while (pid != 0);
    return false;
}

void LinuxSigar::iterate_child_processes(
        sigar_pid_t ppid, sigar::IterateChildProcessCallback callback) {
    std::unordered_map<sigar_pid_t, linux_proc_stat_t> allprocs;

    DIR* dirp = opendir(PROC_FS_ROOT);
    struct dirent* ent;
    if (!dirp) {
        throw std::system_error(
                errno, std::system_category(), "Failed to open /proc");
    }

    while ((ent = readdir(dirp)) != nullptr) {
        if (!sigar_isdigit(*ent->d_name)) {
            continue;
        }

        /* XXX: more sanity checking */
        sigar_pid_t pid = strtoul(ent->d_name, nullptr, 10);
        auto [status, pinfo] = proc_stat_read(pid);
        if (status == SIGAR_OK) {
            allprocs[pid] = std::move(pinfo);
        }
    }
    closedir(dirp);

    for (const auto& [pid, pinfo] : allprocs) {
        if (check_parents(pid, ppid, allprocs)) {
            callback(pid, pinfo.ppid, pinfo.start_time, pinfo.name);
        }
    }
}

int LinuxSigar::get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem) {
    const auto [status, pstat] = proc_stat_read(pid);
    if (status != SIGAR_OK) {
        return status;
    }

    procmem.minor_faults = pstat.minor_faults;
    procmem.major_faults = pstat.major_faults;
    procmem.page_faults = procmem.minor_faults + procmem.major_faults;

    sigar_tokenize_file_line_by_line(
            pid,
            "statm",
            [&procmem, sigar = this](const auto& vec) {
                // The format of statm is a single line with the following
                // numbers (in pages)
                // size resident shared text lib data dirty
                if (vec.size() > 2) {
                    procmem.size = pageshift(std::stoull(std::string(vec[0])));
                    procmem.resident =
                            pageshift(std::stoull(std::string(vec[1])));
                    procmem.share = pageshift(std::stoull(std::string(vec[2])));
                    return false;
                }
                return true;
            },
            ' ');

    return SIGAR_OK;
}

int LinuxSigar::get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime) {
    const auto [status, pstat] = proc_stat_read(pid);
    if (status != SIGAR_OK) {
        return status;
    }

    proctime.user = pstat.utime;
    proctime.sys = pstat.stime;
    proctime.total = proctime.user + proctime.sys;
    proctime.start_time = pstat.start_time;

    return SIGAR_OK;
}

int LinuxSigar::get_proc_state(sigar_pid_t pid, sigar_proc_state_t& procstate) {
    const auto [status, pstat] = proc_stat_read(pid);
    if (status != SIGAR_OK) {
        return status;
    }

    memcpy(procstate.name, pstat.name, sizeof(procstate.name));
    procstate.state = pstat.state;
    procstate.ppid = pstat.ppid;
    procstate.tty = pstat.tty;
    procstate.priority = pstat.priority;
    procstate.nice = pstat.nice;
    procstate.processor = pstat.processor;

    sigar_tokenize_file_line_by_line(
            pid,
            "status",
            [&procstate](const auto& vec) {
                if (vec.size() > 1 && vec.front() == "Threads") {
                    procstate.threads = std::stoull(std::string(vec[1]));
                    return false;
                }
                return true;
            },
            ':');

    return SIGAR_OK;
}
