/*
 *     Copyright 2011 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "sigar_port.h"
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <platform/timeutils.h>
#include <sigar/logger.h>
#include <sigar/sigar.h>
#include <spdlog/common.h>
#ifdef __linux__
#include <cgroup/cgroup.h>
#include <sigar_control_group.h>
#endif
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace sigar_port {
bool human_readable_output = false;
int indentation = -1;
FILE* input = nullptr;
FILE* output = nullptr;
} // namespace sigar_port

using namespace sigar;
using namespace sigar_port;

static inline std::string size2human(std::size_t value) {
    const std::array<const char*, 6> suffix{{"", "K", "M", "G", "T", "P"}};
    std::size_t index = 0;
    while (value > 10240 && index < (suffix.size() - 1)) {
        value /= 1024;
        ++index;
    }
    return std::to_string(value) + suffix[index];
}

std::string size2string(uint64_t value) {
    if (human_readable_output) {
        return size2human(value);
    }

    return std::to_string(value);
}

template <typename T>
std::string time2string(uint64_t value) {
    if (human_readable_output && value) {
        return cb::time2text(T{value});
    }
    return std::to_string(value);
}

std::string ms2string(uint64_t value) {
    return time2string<std::chrono::milliseconds>(value);
}

std::string us2string(uint64_t value) {
    return time2string<std::chrono::microseconds>(value);
}

/// Test to see if a field is implemented (its value is != not implemented)
template <typename Value>
bool is_implemented(Value value) {
    return value != std::numeric_limits<Value>::max();
}

static bool is_interesting_process(std::string_view name) {
    using namespace std::string_view_literals;
    return !(name == "moxi"sv || name == "inet_gethost"sv ||
             name == "memsup"sv || name == "cpu_sup"sv || name == "sh"sv ||
             name == "epmd"sv);
}

struct proc {
    proc(sigar_pid_t pid,
         sigar_pid_t ppid,
         uint64_t start_time,
         std::string name)
        : pid(pid), ppid(ppid), start_time(start_time), name(std::move(name)) {
    }
    sigar_pid_t pid;
    sigar_pid_t ppid;
    uint64_t start_time;
    std::string name;
};

/// Find all of the descendants of the babysitter process and populate the
/// interesting_proc array with the more information about each process
///
/// @param sigar the library handle
/// @param babysitter_pid the pid of the babysitter
/// @return A vector containing all the processes we're interested in
static std::vector<proc> find_interesting_procs(SigarIface& instance,
                                                sigar_pid_t babysitter_pid) {
    sigar_proc_state_t proc_state;
    sigar_proc_cpu_t proc_cpu;

    try {
        proc_state = instance.get_proc_state(babysitter_pid);
        proc_cpu = instance.get_proc_cpu(babysitter_pid);
    } catch (const std::exception& exception) {
        logit(spdlog::level::err,
              fmt::format("Failed to lookup the babysitter process with "
                          "pid {}: {}",
                          babysitter_pid,
                          exception.what()));
        exit(SIGAR_NO_BABYSITTER);
    }

    std::vector<proc> ret;
    ret.emplace_back(babysitter_pid,
                     proc_state.ppid,
                     proc_cpu.start_time,
                     proc_state.name);

    try {
        instance.iterate_child_processes(
                babysitter_pid,
                [&ret](sigar_pid_t pid,
                       sigar_pid_t ppid,
                       uint64_t start_time,
                       std::string_view name) {
                    if (is_interesting_process(name)) {
                        ret.emplace_back(
                                pid, ppid, start_time, std::string{name});
                    }
                });
    } catch (const std::exception& exception) {
        logit(spdlog::level::err,
              fmt::format("Failed to iterate child processes: {}",
                          exception.what()));
    }

    return ret;
}

/// Iterate over all the processes we've considered as interesting and
/// get the details
///
/// @param sigar The handle to sigar
/// @param procs The processes to get information for
/// @return an array containing information of interesting processes
static nlohmann::json populate_interesting_procs(
        SigarIface& instance, const std::vector<proc>& procs) {
    auto json = nlohmann::json::array();

    for (const auto& proc : procs) {
        sigar_proc_mem_t proc_mem;
        sigar_proc_cpu_t proc_cpu;
        try {
            proc_mem = instance.get_proc_memory(proc.pid);
            proc_cpu = instance.get_proc_cpu(proc.pid);
        } catch (const std::exception&) {
            // The process may be gone
            continue;
        }
        if (proc.start_time != proc_cpu.start_time || proc.name.empty()) {
            // The process represented by pid is no longer there, or
            // was replaced by a different process than the last time
            // we checked (or we don't know the process name)
            continue;
        }

        nlohmann::json child = {
                {"name", proc.name.data()},
                {"pid", std::to_string(proc.pid)},
                {"ppid", std::to_string(proc.ppid)},
                {"start_time", std::to_string(proc_cpu.start_time)}};
        if (is_implemented(proc_cpu.user)) {
            child["cpu_user"] = ms2string(proc_cpu.user);
        }
        if (is_implemented(proc_cpu.sys)) {
            child["cpu_sys"] = ms2string(proc_cpu.sys);
        }
        if (is_implemented(proc_mem.size)) {
            child["mem_size"] = size2string(proc_mem.size);
        }
        if (is_implemented(proc_mem.resident)) {
            child["mem_resident"] = size2string(proc_mem.resident);
        }
        if (is_implemented(proc_mem.share)) {
            child["mem_share"] = size2string(proc_mem.share);
        }
        if (is_implemented(proc_mem.minor_faults)) {
            child["minor_faults"] = std::to_string(proc_mem.minor_faults);
        }
        if (is_implemented(proc_mem.major_faults)) {
            child["major_faults"] = std::to_string(proc_mem.major_faults);
        }
        if (is_implemented(proc_mem.page_faults)) {
            child["page_faults"] = std::to_string(proc_mem.page_faults);
        }
        json.emplace_back(std::move(child));
    }

    return json;
}

static nlohmann::json populate_disk_usages(
        std::vector<sigar::disk_usage_t>& disks) {
    auto ret = nlohmann::json::array();

    for (auto& disk : disks) {
        nlohmann::json json;
        json["name"] = disk.name;

        // json specs are inconsistent when it comes to numbers so just use a
        // string everywhere
        if (is_implemented(disk.reads)) {
            json["reads"] = std::to_string(disk.reads);
        }

        if (is_implemented(disk.rbytes)) {
            json["read_bytes"] = size2string(disk.rbytes);
        }

        if (is_implemented(disk.rtime)) {
            json["read_time_ms"] = ms2string(disk.rtime.count());
        }

        if (is_implemented(disk.writes)) {
            json["writes"] = std::to_string(disk.writes);
        }

        if (is_implemented(disk.wbytes)) {
            json["write_bytes"] = size2string(disk.wbytes);
        }

        if (is_implemented(disk.wtime)) {
            json["write_time_ms"] = ms2string(disk.wtime.count());
        }

        if (is_implemented(disk.time)) {
            json["time_ms"] = ms2string(disk.time.count());
        }

        if (is_implemented(disk.queue)) {
            json["queue"] = std::to_string(disk.queue);
        }

        if (is_implemented(disk.queue_depth)) {
            json["queue_depth"] = std::to_string(disk.queue_depth);
        }

        ret.emplace_back(std::move(json));
    }

    return ret;
}

/**
 * Find all of the disks attached to the machine
 *
 * @param sigar the library handle
 * @return A vector containing all of the disks
 */
static std::vector<sigar::disk_usage_t> find_disk_usages(SigarIface& instance) {
    std::vector<sigar::disk_usage_t> ret;

    try {
        instance.iterate_disks([&ret](const sigar::disk_usage_t& disk) {
            ret.push_back(disk);
        });
    } catch (const std::exception& e) {
        logit(spdlog::level::err,
              fmt::format("find_disk_usages(): Received exception: {}",
                          e.what()));
    }

    return ret;
}

uint64_t sum_implemented(uint64_t a, uint64_t b) {
    if (!is_implemented(a) && !is_implemented(b)) {
        return -1ULL;
    }
    uint64_t ret = 0;
    if (is_implemented(a)) {
        ret = a;
    }
    if (is_implemented(b)) {
        ret += b;
    }
    return ret;
}

static nlohmann::json next_sample(SigarIface& instance,
                                  std::optional<sigar_pid_t> babysitter_pid) {
    nlohmann::json ret;
    try {
        const auto cpu = instance.get_cpu();
        if (is_implemented(cpu.total)) {
            ret["cpu_total_ms"] = ms2string(cpu.total);
        }
        uint64_t value = sum_implemented(cpu.idle, cpu.wait);
        if (is_implemented(value)) {
            ret["cpu_idle_ms"] = ms2string(value);
        }
        value = sum_implemented(cpu.user, cpu.nice);
        if (is_implemented(value)) {
            ret["cpu_user_ms"] = ms2string(value);
        }
        if (is_implemented(cpu.sys)) {
            ret["cpu_sys_ms"] = ms2string(cpu.sys);
        }
        value = sum_implemented(cpu.irq, cpu.soft_irq);
        if (is_implemented(value)) {
            ret["cpu_irq_ms"] = ms2string(value);
        }
        if (is_implemented(cpu.stolen)) {
            ret["cpu_stolen_ms"] = ms2string(cpu.stolen);
        }
    } catch (const std::exception& exception) {
        logit(spdlog::level::err,
              fmt::format("Failed to get CPU information: {}",
                          exception.what()));
    }

    try {
        const auto swap = instance.get_swap();
        if (is_implemented(swap.total)) {
            ret["swap_total"] = size2string(swap.total);
        }
        if (is_implemented(swap.used)) {
            ret["swap_used"] = size2string(swap.used);
        }
        if (is_implemented(swap.allocstall)) {
            ret["allocstall"] = std::to_string(swap.allocstall);
        }
    } catch (const std::exception& exception) {
        logit(spdlog::level::err,
              fmt::format("Failed to get swap information: {}",
                          exception.what()));
    }

    try {
        const auto mem = instance.get_memory();
        if (is_implemented(mem.total)) {
            ret["mem_total"] = size2string(mem.total);
        }
        if (is_implemented(mem.used)) {
            ret["mem_used"] = size2string(mem.used);
        }
        if (is_implemented(mem.actual_used)) {
            ret["mem_actual_used"] = size2string(mem.actual_used);
        }
        if (is_implemented(mem.actual_free)) {
            ret["mem_actual_free"] = size2string(mem.actual_free);
        }
    } catch (const std::exception& exception) {
        logit(spdlog::level::err,
              fmt::format("Failed to get memory information: {}",
                          exception.what()));
    }

    if (babysitter_pid) {
        auto procs = find_interesting_procs(instance, babysitter_pid.value());
        auto interesting = populate_interesting_procs(instance, procs);
        if (!interesting.empty()) {
            ret["interesting_procs"] = std::move(interesting);
        }
    }

    auto disks = find_disk_usages(instance);
    if (!disks.empty()) {
        ret["disks"] = populate_disk_usages(disks);
    }

    try {
        const auto cgi = instance.get_control_group_info();
        if (cgi.supported) {
            ret["control_group_info"] = {
                    {"version", int(cgi.version)},
                    {"num_cpu_prc", cgi.num_cpu_prc},
                    {"memory_max", size2string(cgi.memory_max)},
                    {"memory_current", size2string(cgi.memory_current)},
                    {"memory_cache", size2string(cgi.memory_cache)},
                    {"usage_usec", us2string(cgi.usage_usec)},
                    {"user_usec", us2string(cgi.user_usec)},
                    {"system_usec", us2string(cgi.system_usec)},
                    {"nr_periods", std::to_string(cgi.nr_periods)},
                    {"nr_throttled", std::to_string(cgi.nr_throttled)},
                    {"throttled_usec", us2string(cgi.throttled_usec)},
                    {"nr_bursts", std::to_string(cgi.nr_bursts)},
                    {"burst_usec", us2string(cgi.burst_usec)}};
        }
    } catch (const std::exception& exception) {
        logit(spdlog::level::err,
              fmt::format("Failed to get cgroup information: {}",
                          exception.what()));
    }
#ifdef __linux__
    using namespace cb::cgroup;
    auto& cgroup_instance = ControlGroup::instance();
    for (const auto& type :
         {PressureType::Io, PressureType::Memory, PressureType::Cpu}) {
        auto pd = cgroup_instance.get_system_pressure_data(type);
        if (pd) {
            ret["pressure"][to_string(type)] = *pd;
        }

        pd = cgroup_instance.get_pressure_data(type);
        if (pd) {
            ret["control_group_info"]["pressure"][to_string(type)] = *pd;
        }
    }
#endif

    return ret;
}

int sigar_port_snapshot(std::optional<sigar_pid_t> babysitter_pid) {
    std::unique_ptr<SigarIface> instance;
    try {
        instance = SigarIface::New();
    } catch (const std::exception& exception) {
        logit(spdlog::level::err,
              fmt::format("Failed to create sigar instance: {}",
                          exception.what()));
        return SIGAR_INIT_FAIL;
    }

    const auto message =
            next_sample(*instance, babysitter_pid).dump(indentation);
    if (indentation == -1) {
        fprintf(output, "%u\n", int(message.size()));
    }
    fwrite(message.data(), message.size(), 1, output);
    if (indentation != -1) {
        fprintf(output, "\n");
    }
    return SIGAR_NORMAL_EXIT;
}

int sigar_port_main(std::optional<sigar_pid_t> babysitter_pid) {
    std::unique_ptr<SigarIface> instance;
    try {
        instance = SigarIface::New();
    } catch (const std::exception& exception) {
        logit(spdlog::level::err,
              fmt::format("Failed to create sigar instance: {}",
                          exception.what()));
        return SIGAR_INIT_FAIL;
    }

    while (!feof(input)) {
        std::array<char, 80> line;
        if (fgets(line.data(), line.size(), input) == nullptr ||
            ferror(input) || strstr(line.data(), "quit") != nullptr) {
            break;
        }

        const auto message =
                next_sample(*instance, babysitter_pid).dump(indentation);
        fprintf(output, "%u\n", int(message.size()));
        fwrite(message.data(), message.size(), 1, output);
        fflush(output);
    }

    return SIGAR_NORMAL_EXIT;
}
