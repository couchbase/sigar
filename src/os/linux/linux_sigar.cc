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

#include <platform/dirutils.h>
#include <platform/split_string.h>
#include <cerrno>
#include <charconv>
#include <filesystem>
#include <functional>

#include "sigar.h"
#include "sigar_private.h"

#define pageshift(x) ((x)*SystemConstants::instance().pagesize)
#define SIGAR_TICK2MSEC(s) \
    ((uint64_t)(s) *       \
     ((uint64_t)SIGAR_MSEC / (double)SystemConstants::instance().ticks))
#define SIGAR_TICK2USEC(s) \
    ((uint64_t)(s) *       \
     ((uint64_t)SIGAR_USEC / (double)SystemConstants::instance().ticks))

#define sigar_isdigit(c) (isdigit(((unsigned char)(c))))

const char* mock_root = nullptr;

// To allow mocking around with the linux tests just add a prefix
SIGAR_PUBLIC_API void sigar_set_procfs_root(const char* root) {
    mock_root = root;
}

static std::filesystem::path get_proc_root() {
    if (mock_root) {
        return std::filesystem::path{mock_root} / "mock" / "linux" / "proc";
    }
    return std::filesystem::path{"/proc"};
}

void sigar_tokenize_file_line_by_line(
        sigar_pid_t pid,
        const char* filename,
        std::function<bool(const std::vector<std::string_view>&)> callback,
        char delim = ' ') {
    auto name = get_proc_root();
    if (pid) {
        name = name / std::to_string(pid);
    }

    name = name / filename;
    cb::io::tokenizeFileLineByLine(name, callback, delim, false);
}

/// The content of /proc/[pid]/stat (and /proc/[pid]/task/[tid]/stat) file
/// as described in https://man7.org/linux/man-pages/man5/proc.5.html
constexpr size_t stat_pid_index = 1;
constexpr size_t stat_name_index = 2;
constexpr size_t stat_state_index = 3;
constexpr size_t stat_ppid_index = 4;
constexpr size_t stat_tty_index = 7;
constexpr size_t stat_minor_faults_index = 10;
constexpr size_t stat_major_faults_index = 12;
constexpr size_t stat_utime_index = 14;
constexpr size_t stat_stime_index = 15;
constexpr size_t stat_priority_index = 18;
constexpr size_t stat_nice_index = 19;
constexpr size_t stat_start_time_index = 22;
constexpr size_t stat_rss_index = 24;
constexpr size_t stat_processor_index = 39;

struct linux_proc_stat_t {
    sigar_pid_t pid;
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
    std::string name;
    char state;
    int processor;
};

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
    void iterate_threads(sigar::IterateThreadCallback callback) override;

protected:
    int get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime) override;

    static bool check_parents(
            pid_t pid,
            pid_t ppid,
            const std::unordered_map<sigar_pid_t, linux_proc_stat_t>& procs);
    static std::pair<int, linux_proc_stat_t> proc_stat_read(sigar_pid_t pid);
    static linux_proc_stat_t parse_stat_file(const std::filesystem::path& name,
                                             bool use_usec = false);
};

sigar_t::sigar_t() = default;

std::unique_ptr<sigar_t> sigar_t::New() {
    return std::make_unique<LinuxSigar>();
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
            [&cpu, &status](const auto& vec) {
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

linux_proc_stat_t LinuxSigar::parse_stat_file(const std::filesystem::path& name,
                                              bool use_usec) {
    auto content = cb::io::loadFile(name.generic_string(),
                                    std::chrono::microseconds{});
    auto lines = cb::string::split(content, '\n');
    if (lines.size() > 1) {
        throw std::runtime_error("parse_stat_file(): file " +
                                 name.generic_string() +
                                 " contained multiple lines!");
    }

    auto line = std::move(content);
    auto fields = cb::string::split(line, ' ');
    if (fields.size() < stat_processor_index) {
        throw std::runtime_error("parse_stat_file(): file " +
                                 name.generic_string() +
                                 " does not contain enough fields");
    }

    // For some stupid reason the /proc files on linux consists of "formatted
    // ASCII" files so that we need to perform text parsing to pick out the
    // correct values (instead of the "binary" mode used on other systems
    // where you could do an ioctl / read and get the struct populated with
    // the correct values.
    // For "stat" this is extra annoying as space is used as the field
    // separator, but the command line can contain a space it is enclosed
    // in () (so using '\n' instead of ' ' would have made it easier to parse
    // :P ).
    while (fields[1].find(')') == std::string_view::npos) {
        fields[1] = {fields[1].data(), fields[1].size() + fields[2].size() + 1};
        auto iter = fields.begin();
        iter++;
        iter++;
        fields.erase(iter);
        if (fields.size() < stat_processor_index) {
            throw std::runtime_error("parse_stat_file(): file " +
                                     name.generic_string() +
                                     " does not contain enough fields");
        }
    }
    // now remove '(' and ')'
    fields[1].remove_prefix(1);
    fields[1].remove_suffix(1);

    // Insert a dummy 0 element so that the index we use map directly
    // to the number specified in
    // https://man7.org/linux/man-pages/man5/proc.5.html
    fields.insert(fields.begin(), "dummy element");
    linux_proc_stat_t ret;
    ret.pid = stoull(fields[stat_pid_index]);
    ret.name = std::string{fields[stat_name_index].data(),
                           fields[stat_name_index].size()};
    ret.state = fields[stat_state_index].front();
    ret.ppid = stoull(fields[stat_ppid_index]);
    ret.tty = stoull(fields[stat_tty_index]);
    ret.minor_faults = stoull(fields[stat_minor_faults_index]);
    ret.major_faults = stoull(fields[stat_major_faults_index]);
    if (use_usec) {
        ret.utime = SIGAR_TICK2USEC(stoull(fields[stat_utime_index]));
        ret.stime = SIGAR_TICK2USEC(stoull(fields[stat_stime_index]));
    } else {
        ret.utime = SIGAR_TICK2MSEC(stoull(fields[stat_utime_index]));
        ret.stime = SIGAR_TICK2MSEC(stoull(fields[stat_stime_index]));
    }
    ret.priority = stoull(fields[stat_priority_index]);
    ret.nice = stoull(fields[stat_nice_index]);
    ret.start_time = stoull(fields[stat_start_time_index]);
    ret.start_time /= SystemConstants::instance().ticks;
    ret.start_time += SystemConstants::instance().boot_time; /* seconds */
    ret.start_time *= 1000; /* milliseconds */
    ret.rss = stoull(fields[stat_rss_index]);
    ret.processor = stoull(fields[stat_processor_index]);
    return ret;
}

std::pair<int, linux_proc_stat_t> LinuxSigar::proc_stat_read(sigar_pid_t pid) {
    try {
        const auto nm = get_proc_root() / std::to_string(pid) / "stat";
        return {SIGAR_OK, parse_stat_file(nm)};
    } catch (const std::exception& e) {
        return {EINVAL, {}};
    }
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

    for (const auto& p :
         std::filesystem::directory_iterator(get_proc_root())) {
        if (p.path().filename() == std::filesystem::path(".") ||
            p.path().filename() == std::filesystem::path("..")) {
            continue;
        }
        auto child = p.path() / "stat";
        try {
            if (is_regular_file(child)) {
                auto pinfo = parse_stat_file(child);
                allprocs[pinfo.pid] = std::move(pinfo);
            }
        } catch (const std::exception& e) {
            // ignore
        }
    }

    for (const auto& [pid, pinfo] : allprocs) {
        if (check_parents(pid, ppid, allprocs)) {
            callback(pid, pinfo.ppid, pinfo.start_time, pinfo.name.c_str());
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
            [&procmem](const auto& vec) {
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
    auto [status, pstat] = proc_stat_read(pid);
    if (status != SIGAR_OK) {
        return status;
    }

    // according to the proc manpage pstat.name contains up to 16 characters,
    // and procstate.name is 128 bytes large, but to be on the safe side ;)
    if (pstat.name.length() > sizeof(procstate.name) - 1) {
        pstat.name.resize(sizeof(procstate.name) - 1);
    }
    strcpy(procstate.name, pstat.name.c_str());
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

void LinuxSigar::iterate_threads(sigar::IterateThreadCallback callback) {
    auto dir =
            std::filesystem::path("/proc") / std::to_string(getpid()) / "task";

    for (const auto& p : std::filesystem::directory_iterator(dir)) {
        if (std::filesystem::is_directory(p) &&
            p.path().filename().string().find('.') != 0) {
            auto statfile = p.path() / "stat";
            if (exists(statfile)) {
                try {
                    const auto tid = std::stoull(p.path().filename().string());
                    auto info = parse_stat_file(statfile, true);
                    callback(tid, info.name, info.utime, info.stime);
                } catch (const std::exception&) {
                    // ignore
                }
            }
        }
    }
}
