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
#include <sigar/sigar.h>

#if defined(__linux__) || defined(__APPLE__)

#include "sigar.h"
#include "sigar_private.h"

#include <cgroup/cgroup.h>
#include <platform/dirutils.h>
#include <platform/split_string.h>
#include <unistd.h>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <functional>
#include <optional>
#include <unordered_map>

namespace sigar {

#define pageshift(x) ((x)*SystemConstants::instance().pagesize)
#define SIGAR_TICK2MSEC(s) \
    ((uint64_t)(s) *       \
     ((uint64_t)SIGAR_MSEC / (double)SystemConstants::instance().ticks))
#define SIGAR_TICK2USEC(s) \
    ((uint64_t)(s) *       \
     ((uint64_t)SIGAR_USEC / (double)SystemConstants::instance().ticks))

static std::filesystem::path mock_root;
void SigarIface::set_mock_root(std::filesystem::path root) {
    if (!root.empty() && !is_directory(root)) {
        throw std::runtime_error(
                "SigarIface::set_mock_root: The provided directory must exists "
                "and be a directory");
    }
    mock_root = std::move(root);
}

static std::filesystem::path get_proc_root() {
    if (mock_root.empty()) {
        return std::filesystem::path{"/proc"};
    }

    return mock_root / "mock" / "linux" / "proc";
}

static std::filesystem::path get_sys_root() {
    if (mock_root.empty()) {
        return std::filesystem::path{"/sys"};
    }
    return mock_root / "mock" / "linux" / "sys";
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
constexpr size_t stat_ppid_index = 4;
constexpr size_t stat_minor_faults_index = 10;
constexpr size_t stat_major_faults_index = 12;
constexpr size_t stat_utime_index = 14;
constexpr size_t stat_stime_index = 15;
constexpr size_t stat_start_time_index = 22;
constexpr size_t stat_rss_index = 24;

struct linux_proc_stat_t {
    sigar_pid_t pid;
    uint64_t rss;
    uint64_t minor_faults;
    uint64_t major_faults;
    uint64_t ppid;
    uint64_t start_time;
    uint64_t utime;
    uint64_t stime;
    std::string name;
};

struct SystemConstants {
    static SystemConstants instance() {
        static SystemConstants inst;
        return inst;
    }

    SystemConstants()
        : pagesize(
#ifdef __APPLE__
                  // The mock files was collected on a system with a
                  // 4k; we need to use that ;-)
                  4096
#else
                  getpagesize()
#endif
                  ),
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

class LinuxSigar : public SigarIface {
public:
    sigar_mem_t get_memory() override;
    sigar_swap_t get_swap() override;
    sigar_cpu_t get_cpu() override;
    sigar_proc_mem_t get_proc_memory(sigar_pid_t pid) override;
    sigar_proc_state_t get_proc_state(sigar_pid_t pid) override;
    void iterate_child_processes(
            sigar_pid_t pid,
            sigar::IterateChildProcessCallback callback) override;
    void iterate_threads(sigar::IterateThreadCallback callback) override;
    void iterate_disks(sigar::IterateDiskCallback callback) override;
    sigar_control_group_info get_control_group_info() const override;
    sigar_proc_cpu_t get_proc_cpu(sigar_pid_t pid) const override;

protected:
    static bool check_parents(
            pid_t pid,
            pid_t ppid,
            const std::unordered_map<sigar_pid_t, linux_proc_stat_t>& procs);
    static linux_proc_stat_t parse_stat_file(const std::filesystem::path& name,
                                             bool use_usec = false);

    static std::optional<uint64_t> get_device_queue_depth(
            std::string_view name);

    static linux_proc_stat_t proc_stat_read(sigar_pid_t pid) {
        return parse_stat_file(get_proc_root() / std::to_string(pid) / "stat");
    }
};

std::unique_ptr<SigarIface> NewLinuxSigar() {
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

sigar_mem_t LinuxSigar::get_memory() {
    sigar_mem_t mem;
    sigar_tokenize_file_line_by_line(
            0,
            "meminfo",
            [&mem](const auto& vec) {
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
                if (vec.front() == "MemAvailable") {
                    mem.actual_free = stoull(vec[1]);
                    return true;
                }
                return true;
            },
            ':');

    mem.used = mem.total - mem.free;
    mem.actual_used = mem.total - mem.actual_free;
    return mem;
}

sigar_swap_t LinuxSigar::get_swap() {
    sigar_swap_t swap;
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
    swap.allocstall = 0;
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
                } else if (vec.front() == "allocstall" ||
                           vec.front() == "allocstall_dma" ||
                           vec.front() == "allocstall_dma32" ||
                           vec.front() == "allocstall_normal" ||
                           vec.front() == "allocstall_movable") {
                    swap.allocstall += stoull(vec[1]);
                }

                return true;
            },
            ' ');

    return swap;
}

sigar_cpu_t LinuxSigar::get_cpu() {
    sigar_cpu_t cpu;
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

    if (status != SIGAR_OK) {
        throw std::system_error(
                std::error_code(status, std::system_category()),
                "LinuxSigar::get_cpu(): failed to parse /proc/stat");
    }
    return cpu;
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
    if (fields.size() < stat_rss_index) {
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
        if (fields.size() < stat_rss_index) {
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
    ret.ppid = stoull(fields[stat_ppid_index]);
    ret.minor_faults = stoull(fields[stat_minor_faults_index]);
    ret.major_faults = stoull(fields[stat_major_faults_index]);
    if (use_usec) {
        ret.utime = SIGAR_TICK2USEC(stoull(fields[stat_utime_index]));
        ret.stime = SIGAR_TICK2USEC(stoull(fields[stat_stime_index]));
    } else {
        ret.utime = SIGAR_TICK2MSEC(stoull(fields[stat_utime_index]));
        ret.stime = SIGAR_TICK2MSEC(stoull(fields[stat_stime_index]));
    }
    ret.start_time = stoull(fields[stat_start_time_index]);
    ret.start_time /= SystemConstants::instance().ticks;
    ret.start_time += SystemConstants::instance().boot_time; /* seconds */
    ret.start_time *= 1000; /* milliseconds */
    ret.rss = stoull(fields[stat_rss_index]);
    return ret;
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

    for (const auto& p : std::filesystem::directory_iterator(get_proc_root())) {
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

sigar_proc_mem_t LinuxSigar::get_proc_memory(sigar_pid_t pid) {
    const auto pstat = proc_stat_read(pid);

    sigar_proc_mem_t procmem;
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

    return procmem;
}

sigar_proc_cpu_t LinuxSigar::get_proc_cpu(sigar_pid_t pid) const {
    const auto pstat = proc_stat_read(pid);
    return {pstat.start_time, pstat.utime, pstat.stime};
}

sigar_proc_state_t LinuxSigar::get_proc_state(sigar_pid_t pid) {
    auto pstat = proc_stat_read(pid);
    sigar_proc_state_t procstate;

    // according to the proc manpage pstat.name contains up to 16 characters,
    // and procstate.name is 128 bytes large, but to be on the safe side ;)
    if (pstat.name.length() > sizeof(procstate.name) - 1) {
        pstat.name.resize(sizeof(procstate.name) - 1);
    }
    strcpy(procstate.name, pstat.name.c_str());
    procstate.ppid = pstat.ppid;

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

    return procstate;
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

std::optional<uint64_t> LinuxSigar::get_device_queue_depth(
        std::string_view name) {
    try {
        auto file = get_sys_root() / "block" / name / "device" / "queue_depth";
        return stoull(cb::io::loadFile(file));
    } catch (const std::exception& e) {
        // We don't expect files to exist for any non-physical drive so just
        // ignore the errors.
        return {};
    }
}

void LinuxSigar::iterate_disks(sigar::IterateDiskCallback callback) {
    sigar_tokenize_file_line_by_line(
            0,
            "diskstats",
            [&callback](const auto& vec) {
                /**
                 * https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats
                 * =  ====================================
                 * 1  major number
                 * 2  minor mumber
                 * 3  device name
                 * 4  reads completed successfully
                 * 5  reads merged
                 * 6  sectors read
                 * 7  time spent reading (ms)
                 * 8  writes completed
                 * 9  writes merged
                 * 10  sectors written
                 * 11  time spent writing (ms)
                 * 12  I/Os currently in progress
                 * 13  time spent doing I/Os (ms)
                 * 14  weighted time spent doing I/Os (ms)
                 * ==  ===================================
                 *
                 * Kernel 4.18+ appends four more fields for discard
                 * tracking putting the total at 18:
                 *
                 * ==  ===================================
                 * 15  discards completed successfully
                 * 16  discards merged
                 * 17  sectors discarded
                 * 18  time spent discarding
                 * ==  ===================================
                 *
                 * Kernel 5.5+ appends two more fields for flush requests:
                 *
                 * ==  =====================================
                 * 19  flush requests completed successfully
                 * 20  time spent flushing
                 * ==  =====================================
                 */
                if (vec.size() < 14) {
                    return false;
                }

                static const auto sigar_sector_size = 512;

                sigar::disk_usage_t disk;

                // First column is whitespace for some reason.
                // Next two columns are not interesting to us...
                disk.name = vec[3];

                disk.reads = stoull(vec[4]);
                disk.rbytes = stoull(vec[6]) * sigar_sector_size;
                disk.rtime = std::chrono::milliseconds(stoull(vec[7]));

                disk.writes = stoull(vec[8]);
                disk.wbytes = stoull(vec[10]) * sigar_sector_size;
                disk.wtime = std::chrono::milliseconds(stoull(vec[11]));

                disk.queue = stoull(vec[12]);
                disk.time = std::chrono::milliseconds(stoull(vec[13]));

                if (auto queue_depth = get_device_queue_depth(disk.name)) {
                    disk.queue_depth = *queue_depth;
                }

                callback(disk);
                return true;
            },
            ' ');
}

sigar_control_group_info LinuxSigar::get_control_group_info() const {
    auto& cg = cb::cgroup::ControlGroup::instance();
    sigar_control_group_info info;
    info.supported = 1;
    info.version = uint8_t(cg.get_version());
    info.num_cpu_prc = uint16_t(cg.get_available_cpu());
    info.memory_max = cg.get_max_memory();
    info.memory_current = cg.get_current_memory();
    info.memory_cache = cg.get_current_cache_memory();
    const auto stats = cg.get_cpu_stats();
    info.usage_usec = stats.usage.count();
    info.user_usec = stats.user.count();
    info.system_usec = stats.system.count();
    info.nr_periods = stats.nr_periods;
    info.nr_throttled = stats.nr_throttled;
    info.throttled_usec = stats.throttled.count();
    info.nr_bursts = stats.nr_bursts;
    info.burst_usec = stats.burst.count();
    return info;
}
} // namespace sigar
#else
namespace sigar {
std::unique_ptr<SigarIface> NewLinuxSigar() {
    return {};
}
} // namespace sigar
#endif
