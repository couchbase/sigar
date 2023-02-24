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

#ifndef WIN32
#include <unistd.h>
#endif

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
            {"ppid", to_string(proc.ppid)}};
    if (is_implemented(proc.mem_size)) {
        json["mem_size"] = std::to_string(proc.mem_size);
    }
    if (is_implemented(proc.mem_resident)) {
        json["mem_resident"] = std::to_string(proc.mem_resident);
    }
    if (is_implemented(proc.mem_share)) {
        json["mem_share"] = std::to_string(proc.mem_share);
    }
    if (is_implemented(proc.minor_faults)) {
        json["minor_faults"] = std::to_string(proc.minor_faults);
    }
    if (is_implemented(proc.major_faults)) {
        json["major_faults"] = std::to_string(proc.major_faults);
    }
    if (is_implemented(proc.page_faults)) {
        json["page_faults"] = std::to_string(proc.page_faults);
    }
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
    json = {{"version", stats.version}};

    if (is_implemented(stats.cpu_total_ms)) {
        json["cpu_total_ms"] = std::to_string(stats.cpu_total_ms);
    }

    if (is_implemented(stats.cpu_idle_ms)) {
        json["cpu_idle_ms"] = std::to_string(stats.cpu_idle_ms);
    }

    if (is_implemented(stats.cpu_user_ms)) {
        json["cpu_user_ms"] = std::to_string(stats.cpu_user_ms);
    }

    if (is_implemented(stats.cpu_sys_ms)) {
        json["cpu_sys_ms"] = std::to_string(stats.cpu_sys_ms);
    }

    if (is_implemented(stats.cpu_irq_ms)) {
        json["cpu_irq_ms"] = std::to_string(stats.cpu_irq_ms);
    }

    if (is_implemented(stats.cpu_stolen_ms)) {
        json["cpu_stolen_ms"] = std::to_string(stats.cpu_stolen_ms);
    }

    if (is_implemented(stats.swap_total)) {
        json["swap_total"] = std::to_string(stats.swap_total);
    }

    if (is_implemented(stats.swap_used)) {
        json["swap_used"] = std::to_string(stats.swap_used);
    }

    if (is_implemented(stats.mem_total)) {
        json["mem_total"] = std::to_string(stats.mem_total);
    }

    if (is_implemented(stats.mem_used)) {
        json["mem_used"] = std::to_string(stats.mem_used);
    }

    if (is_implemented(stats.mem_actual_used)) {
        json["mem_actual_used"] = std::to_string(stats.mem_actual_used);
    }

    if (is_implemented(stats.mem_actual_free)) {
        json["mem_actual_free"] = std::to_string(stats.mem_actual_free);
    }

    if (is_implemented(stats.allocstall)) {
        json["allocstall"] = std::to_string(stats.allocstall);
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

/// Iterate over all the processes we've considered as interesting and
/// push the details for the process into the reply.
///
/// @param sigar The handle to sigar
/// @param procs The processes to get information for
/// @param reply Where to store the data
static void populate_interesting_procs(sigar_t* sigar,
                                       const std::vector<proc>& procs,
                                       system_stats& reply) {
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
            continue;
        }
        proc_stats& child = *iter;
        child.pid = proc.pid;
        child.ppid = proc.ppid;
        strncpy(child.name.data(), proc.name.c_str(), child.name.size());
        child.cpu_utilization = (uint32_t)(100 * proc_cpu.percent);
        child.mem_size = proc_mem.size;
        child.mem_resident = proc_mem.resident;
        child.mem_share = proc_mem.share;
        child.minor_faults = proc_mem.minor_faults;
        child.major_faults = proc_mem.major_faults;
        child.page_faults = proc_mem.page_faults;
        if (++iter == reply.interesting_procs.end()) {
            // We can't store more processes
            break;
        }
    }
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

system_stats next_sample(sigar_t* instance,
                         std::optional<sigar_pid_t> babysitter_pid) {
    sigar_mem_t mem;
    sigar_swap_t swap;
    sigar_cpu_t cpu;
    struct system_stats reply;

    memset(&reply, 0, sizeof(reply));
    reply.version = CURRENT_SYSTEM_STAT_VERSION;
    reply.struct_size = sizeof(reply);

    sigar_cpu_get(instance, &cpu);
    reply.cpu_total_ms = cpu.total;
    reply.cpu_idle_ms = sum_implemented(cpu.idle, cpu.wait);
    reply.cpu_user_ms = sum_implemented(cpu.user, cpu.nice);
    reply.cpu_sys_ms = cpu.sys;
    reply.cpu_irq_ms = sum_implemented(cpu.irq, cpu.soft_irq);
    reply.cpu_stolen_ms = cpu.stolen;

    sigar_swap_get(instance, &swap);
    reply.swap_total = swap.total;
    reply.swap_used = swap.used;
    reply.allocstall = swap.allocstall;

    sigar_mem_get(instance, &mem);
    reply.mem_total = mem.total;
    reply.mem_used = mem.used;
    reply.mem_actual_used = mem.actual_used;
    reply.mem_actual_free = mem.actual_free;

    if (babysitter_pid) {
        auto procs = find_interesting_procs(instance, babysitter_pid.value());
        populate_interesting_procs(instance, procs, reply);
    }

    sigar_get_control_group_info(&reply.control_group_info);
    return reply;
}

int sigar_port_main(std::optional<sigar_pid_t> babysitter_pid,
                    OutputFormat format,
                    FILE* in,
                    FILE* out) {
    sigar_t* sigar;

#ifdef WIN32
    const int indentation = -1;
#else
    const int indentation =
            (isatty(fileno(in)) || isatty(fileno(out))) ? 2 : -1;
#endif

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

        auto reply = next_sample(sigar, babysitter_pid);

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

            const auto message = data.dump(indentation);
            fprintf(out, "%u\n", int(message.size()));
            fwrite(message.data(), message.size(), 1, out);
        }
        fflush(out);
    }

    sigar_close(sigar);
    return 0;
}
