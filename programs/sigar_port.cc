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

#ifdef __linux__
#include <cgroup/cgroup.h>
#endif
#include <nlohmann/json.hpp>
#include <sigar.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

/// Test to see if a field is implemented (its value is != not implemented)
template <typename Value>
bool is_implemented(Value value) {
    return value != std::numeric_limits<Value>::max();
}

template <typename Value>
std::string to_string(Value value) {
    if (is_implemented(value)) {
        return std::to_string(value);
    }
    return "-1";
}

void to_json(nlohmann::json& json, const proc_stats& proc) {
    json = {{"name", proc.name.data()},
            {"cpu_utilization", to_string(proc.cpu_utilization)},
            {"pid", to_string(proc.pid)},
            {"ppid", to_string(proc.ppid)},
            {"mem_size", to_string(proc.mem_size)},
            {"mem_resident", to_string(proc.mem_resident)},
            {"mem_share", to_string(proc.mem_share)},
            {"minor_faults", to_string(proc.minor_faults)},
            {"major_faults", to_string(proc.major_faults)},
            {"page_faults", to_string(proc.page_faults)}};
}

void to_json(nlohmann::json& json, const sigar_control_group_info_t& cg) {
    json = {{"version", int(cg.version)},
            {"num_cpu_prc", cg.num_cpu_prc},
            {"memory_max", to_string(cg.memory_max)},
            {"memory_current", to_string(cg.memory_current)},
            {"memory_cache", to_string(cg.memory_cache)},
            {"usage_usec", to_string(cg.usage_usec)},
            {"user_usec", to_string(cg.user_usec)},
            {"system_usec", to_string(cg.system_usec)},
            {"nr_periods", to_string(cg.nr_periods)},
            {"nr_throttled", to_string(cg.nr_throttled)},
            {"throttled_usec", to_string(cg.throttled_usec)},
            {"nr_bursts", to_string(cg.nr_bursts)},
            {"burst_usec", to_string(cg.burst_usec)}};
}

void to_json(nlohmann::json& json, const system_stats& stats) {
    json = {{"version", stats.version},
            {"cpu_total_ms", to_string(stats.cpu_total_ms)},
            {"cpu_idle_ms", to_string(stats.cpu_idle_ms)},
            {"cpu_user_ms", to_string(stats.cpu_user_ms)},
            {"cpu_sys_ms", to_string(stats.cpu_sys_ms)},
            {"cpu_irq_ms", to_string(stats.cpu_irq_ms)},
            {"cpu_stolen_ms", to_string(stats.cpu_stolen_ms)},
            {"swap_total", to_string(stats.swap_total)},
            {"swap_used", to_string(stats.swap_used)},
            {"mem_total", to_string(stats.mem_total)},
            {"mem_used", to_string(stats.mem_used)},
            {"mem_actual_used", to_string(stats.mem_actual_used)},
            {"mem_actual_free", to_string(stats.mem_actual_free)}};

    if (is_implemented(stats.allocstall)) {
        json["allocstall"] = to_string(stats.allocstall);
    }

    if (stats.control_group_info.supported) {
        json["control_group_info"] = stats.control_group_info;
    }

    for (const auto& proc : stats.interesting_procs) {
        if (proc.name[0] != '\0') {
            json["interesting_procs"].emplace_back(proc);
        }
    }
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
static std::vector<proc> find_interesting_procs(sigar_t* sigar,
                                                sigar_pid_t babysitter_pid) {
    sigar_proc_state_t proc_state;
    sigar_proc_cpu_t proc_cpu;

    if (sigar_proc_state_get(sigar, babysitter_pid, &proc_state) != SIGAR_OK ||
        sigar_proc_cpu_get(sigar, babysitter_pid, &proc_cpu) != SIGAR_OK) {
        fprintf(stderr,
                "Failed to lookup the babysitter process with pid %u",
                babysitter_pid);
        exit(1);
    }

    std::vector<proc> ret;
    ret.emplace_back(babysitter_pid,
                     proc_state.ppid,
                     proc_cpu.start_time,
                     proc_state.name);

    try {
        sigar::iterate_child_processes(
                sigar,
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
    } catch (const std::exception&) {
        // ignore
    }

    return ret;
}

constexpr int PROCS_REFRESH_INTERVAL = 20;

/// Iterate over all the processes we've considered as interesting and
/// push the details for the process into the reply.
///
/// @param sigar The handle to sigar
/// @param procs The processes to get information for
/// @param reply Where to store the data
static bool populate_interesting_procs(sigar_t* sigar,
                                       const std::vector<proc>& procs,
                                       system_stats& reply) {
    bool stale = false;

    sigar_proc_mem_t proc_mem;
    sigar_proc_cpu_t proc_cpu;

    auto iter = reply.interesting_procs.begin();
    for (const auto& proc : procs) {
        if (sigar_proc_mem_get(sigar, proc.pid, &proc_mem) != SIGAR_OK ||
            sigar_proc_cpu_get(sigar, proc.pid, &proc_cpu) != SIGAR_OK ||
            proc.start_time != proc_cpu.start_time) {
            // The process represented by pid is no longer there, or
            // was replaced by a different process than the last time
            // we checked.
            stale = true;
            continue;
        }
        proc_stats& child = *iter;
        child.pid = proc.pid;
        child.ppid = proc.ppid;
        strncpy(child.name.data(), proc.name.c_str(), child.name.size());
        child.cpu_utilization = (uint32_t)(100 * proc_cpu.percent);
        child.mem_size = is_implemented(proc_mem.size) ? proc_mem.size : 0;
        child.mem_resident =
                is_implemented(proc_mem.resident) ? proc_mem.resident : 0;
        child.mem_share = is_implemented(proc_mem.share) ? proc_mem.share : 0;
        child.minor_faults = is_implemented(proc_mem.minor_faults)
                                     ? proc_mem.minor_faults
                                     : 0;
        child.major_faults = is_implemented(proc_mem.major_faults)
                                     ? proc_mem.major_faults
                                     : 0;
        child.page_faults =
                is_implemented(proc_mem.page_faults) ? proc_mem.page_faults : 0;
        if (++iter == reply.interesting_procs.end()) {
            // We can't store more processes
            break;
        }
    }

    return stale;
}

int sigar_port_main(sigar_pid_t babysitter_pid,
                    OutputFormat format,
                    FILE* in,
                    FILE* out) {
    sigar_t* sigar;
    sigar_mem_t mem;
    sigar_swap_t swap;
    sigar_cpu_t cpu;
    struct system_stats reply;

    bool procs_stale = true;
    std::vector<proc> procs;

    int ticks_to_refresh = PROCS_REFRESH_INTERVAL;

    if (sigar_open(&sigar) != SIGAR_OK) {
        fprintf(stderr, "Failed to open sigar\n");
        std::exit(1);
    }

    while (!feof(in)) {
        if (format == OutputFormat::Raw) {
            int req;
            int rv = fread(&req, sizeof(req), 1, in);
            if (rv < 1) {
                continue;
            }
            if (req != 0) {
                break;
            }
        } else {
            std::array<char, 80> line;
            if (fgets(line.data(), line.size(), in) == nullptr || ferror(in) ||
                strstr(line.data(), "quit") != nullptr) {
                break;
            }
        }

        memset(&reply, 0, sizeof(reply));
        reply.version = CURRENT_SYSTEM_STAT_VERSION;
        reply.struct_size = sizeof(reply);

        sigar_mem_get(sigar, &mem);
        sigar_swap_get(sigar, &swap);
        sigar_cpu_get(sigar, &cpu);

        reply.cpu_total_ms = cpu.total;
        reply.cpu_idle_ms = cpu.idle + cpu.wait;
        reply.cpu_user_ms = cpu.user + cpu.nice;
        reply.cpu_sys_ms = cpu.sys;
        reply.cpu_irq_ms = cpu.irq + cpu.soft_irq;
        reply.cpu_stolen_ms = cpu.stolen;

        reply.swap_total = swap.total;
        reply.swap_used = swap.used;
        reply.allocstall = swap.allocstall;

        reply.mem_total = mem.total;
        reply.mem_used = mem.used;
        reply.mem_actual_used = mem.actual_used;
        reply.mem_actual_free = mem.actual_free;

        if (procs_stale || ticks_to_refresh-- == 0) {
            ticks_to_refresh = PROCS_REFRESH_INTERVAL;
            procs = find_interesting_procs(sigar, babysitter_pid);
        }

        procs_stale = populate_interesting_procs(sigar, procs, reply);

        sigar_get_control_group_info(&reply.control_group_info);

        if (format == OutputFormat::Raw) {
            fwrite(&reply, sizeof(reply), 1, out);
        } else {
            nlohmann::json data = reply;

#ifdef __linux__
            using namespace cb::cgroup;
            auto& instance = ControlGroup::instance();
            for (const auto& type :
                 std::vector<cb::cgroup::PressureType>{{PressureType::Io,
                                                        PressureType::Memory,
                                                        PressureType::Cpu}}) {
                auto pd = instance.get_system_pressure_data(type);
                if (pd) {
                    data["pressure"][to_string(type)] = *pd;
                }

                pd = instance.get_pressure_data(type);
                if (pd) {
                    data["control_group_info"]["pressure"][to_string(type)] =
                            *pd;
                }
            }
#endif

            const auto message =
                    data.dump(format == OutputFormat::JsonPretty ? 2 : 0);
            fprintf(out, "%u\n", int(message.size()));
            fwrite(message.data(), message.size(), 1, out);
        }
        fflush(out);
    }

    sigar_close(sigar);
    return 0;
}
