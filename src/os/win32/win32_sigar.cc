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

#include <sigar/sigar.h>

#ifdef WIN32

#include <sigar/logger.h>

#include "sigar.h"
#include "sigar_private.h"

#include <windows.h>

#include <lm.h>
#include <process.h>
#include <processthreadsapi.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <platform/platform_thread.h>
#include <system_error>
#include <vector>

#define EPOCH_DELTA 11644473600000000L

namespace sigar {
struct sigar_win32_pinfo_t {
    sigar_pid_t pid;
    int ppid;
    uint64_t size;
    uint64_t resident;
    char name[SIGAR_PROC_NAME_LEN];
    uint64_t threads;
    uint64_t page_faults;
};

struct AllPidInfo {
    sigar_pid_t pid = 0;
    sigar_pid_t ppid = 0;
    std::string name;
    uint64_t start_time = 0;
};

class Win32Sigar : public SigarIface {
public:
    Win32Sigar();

    ~Win32Sigar() override {
    }

    sigar_mem_t get_memory() override;
    sigar_swap_t get_swap() override;
    sigar_cpu_t get_cpu() override;
    sigar_proc_mem_t get_proc_memory(sigar_pid_t pid) override;
    sigar_proc_state_t get_proc_state(sigar_pid_t pid) override;
    void iterate_child_processes(
            sigar_pid_t ppid,
            sigar::IterateChildProcessCallback callback) override;
    void iterate_threads(sigar::IterateThreadCallback callback) override;
    void iterate_disks(sigar::IterateDiskCallback callback) override;
    sigar_control_group_info get_control_group_info() const override {
        sigar_control_group_info ret;
        ret.supported = false;
        return ret;
    }

protected:
    std::tuple<uint64_t, uint64_t, uint64_t, uint64_t> get_proc_time(
            sigar_pid_t pid) override;
    static void enable_debug_privilege();
    static void log_user_information();

    bool check_parents(
            sigar_pid_t pid,
            sigar_pid_t ppid,
            const std::unordered_map<sigar_pid_t, AllPidInfo>& allprocinfo);

    std::unordered_map<sigar_pid_t, AllPidInfo> get_all_pids();
    std::pair<int, sigar_win32_pinfo_t> get_proc_info(sigar_pid_t pid);
};

/* 1/100ns units to milliseconds */
#define NS100_2MSEC(t) ((t) / 10000)
/* 1/100ns units to microseconds */
#define NS100_2USEC(t) ((t) / 10)

static uint64_t sigar_FileTimeToTime(FILETIME* ft) {
    uint64_t time;
    time = ft->dwHighDateTime;
    time = time << 32;
    time |= ft->dwLowDateTime;
    time /= 10;
    time -= EPOCH_DELTA;
    return time;
}

void Win32Sigar::enable_debug_privilege() {
    HANDLE handle;
    TOKEN_PRIVILEGES tok;
    memset(&tok, 0, sizeof(tok));

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &handle)) {
        return;
    }

    if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tok.Privileges[0].Luid)) {
        tok.PrivilegeCount = 1;
        tok.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(handle, FALSE, &tok, 0, nullptr, 0);
    }

    CloseHandle(handle);
}

static std::string to_string(const wchar_t* ptr) {
    char buffer[1024];
    int size = wcstombs(buffer, ptr, sizeof(buffer));
    return std::string(buffer, size);
}

void Win32Sigar::log_user_information() {
    try {
        wchar_t user[1024];
        DWORD size = sizeof(user) / sizeof(wchar_t);
        nlohmann::json json;

        if (GetUserNameW(user, &size)) {
            json["user"] = to_string(user);
        }

        LPBYTE buffer = nullptr;
        DWORD entries = 0;
        DWORD total_entries = 0;
        if (NetUserGetLocalGroups(nullptr,
                                  user,
                                  0,
                                  LG_INCLUDE_INDIRECT,
                                  &buffer,
                                  MAX_PREFERRED_LENGTH,
                                  &entries,
                                  &total_entries) == NERR_Success) {
            nlohmann::json grps = nlohmann::json::array();
            auto* groups = reinterpret_cast<LOCALGROUP_USERS_INFO_0*>(buffer);
            for (int ii = 0; ii < entries; ii++) {
                grps.push_back(to_string(groups[ii].lgrui0_name));
            }

            NetApiBufferFree(buffer);
            json["local_groups"] = std::move(grps);
            buffer = nullptr;
            entries = 0;
            total_entries = 0;
        }

        if (NetUserGetGroups(nullptr,
                             user,
                             0,
                             &buffer,
                             MAX_PREFERRED_LENGTH,
                             &entries,
                             &total_entries) == NERR_Success) {
            nlohmann::json grps = nlohmann::json::array();
            auto* ggroups = reinterpret_cast<GROUP_USERS_INFO_0*>(buffer);
            for (int ii = 0; ii < entries; ii++) {
                grps.push_back(to_string(ggroups[ii].grui0_name));
            }
            NetApiBufferFree(buffer);
            json["global_groups"] = std::move(grps);
        }

        if (!json.empty()) {
            sigar::logit(sigar::loglevel::info,
                         fmt::format("Running as: {}", json.dump()));
        }
    } catch (const std::exception& e) {
        sigar::logit(sigar::loglevel::err,
                     fmt::format("Failed to determine user id: {}", e.what()));
    }
}

Win32Sigar::Win32Sigar() : SigarIface() {
    enable_debug_privilege();
    log_user_information();
}

std::unique_ptr<SigarIface> NewWin32Sigar() {
    return std::make_unique<Win32Sigar>();
}

sigar_mem_t Win32Sigar::get_memory() {
    sigar_mem_t mem;

    PERFORMANCE_INFORMATION pe;
    pe.cb = sizeof(pe);
    if (!GetPerformanceInfo(&pe, sizeof(pe))) {
        throw std::system_error(
                std::error_code(GetLastError(), std::system_category()),
                "Win32Sigar::get_memory(): GetPerformanceInfo failed");
    }

    mem.total = uint64_t(pe.PhysicalTotal) * pe.PageSize;
    mem.actual_free = mem.free = uint64_t(pe.PhysicalAvailable) * pe.PageSize;
    mem.actual_used = mem.used = mem.total - mem.free;

    // According to the docs:
    //   The amount of system cache memory, in pages.
    //   This is the size of the standby list plus the system working set.
    //
    // I haven't found a good breakdown what exactly this "cache" contains
    // of, but the following "adjustment" caused overflows so we should
    // probably just leave the cache as used.
    //
    //    auto system_cache = pe.SystemCache * pe.PageSize;
    //    mem.actual_free = mem.free + system_cache;
    //    mem.actual_used = mem.used - system_cache;

    return mem;
}

sigar_swap_t Win32Sigar::get_swap() {
    sigar_swap_t swap;
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);

    if (!GlobalMemoryStatusEx(&memstat)) {
        throw std::system_error(
                std::error_code(GetLastError(), std::system_category()),
                "Win32Sigar::get_swap(): GlobalMemoryStatusEx");
    }

    swap.total = memstat.ullTotalPageFile;
    swap.free = memstat.ullAvailPageFile;
    swap.used = swap.total - swap.free;

    return swap;
}

static uint64_t filetime2uint(const FILETIME& val) {
    ULARGE_INTEGER ularge;
    ularge.u.LowPart = val.dwLowDateTime;
    ularge.u.HighPart = val.dwHighDateTime;
    return ularge.QuadPart;
}

sigar_cpu_t Win32Sigar::get_cpu() {
    sigar_cpu_t cpu;
    FILETIME idle, kernel, user;
    if (!GetSystemTimes(&idle, &kernel, &user)) {
        throw std::system_error(
                std::error_code(GetLastError(), std::system_category()),
                "Win32Sigar::get_cpu(): GetSystemTimes");
    }
    cpu.idle = NS100_2MSEC(filetime2uint(idle));
    cpu.sys = NS100_2MSEC(filetime2uint(kernel)) - cpu.idle;
    cpu.user = NS100_2MSEC(filetime2uint(user));
    cpu.total = cpu.idle + cpu.user + cpu.sys;
    return cpu;
}

std::unordered_map<sigar_pid_t, AllPidInfo> Win32Sigar::get_all_pids() {
    std::unordered_map<sigar_pid_t, AllPidInfo> allpids;
    const auto pid = getpid();
    auto snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshotHandle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("CreateToolhelp32Snapshot: failed " +
                                 std::to_string(GetLastError()));
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);

    if (!Process32First(snapshotHandle, &entry)) {
        CloseHandle(snapshotHandle);
        throw std::runtime_error("Process32First: failed " +
                                 std::to_string(GetLastError()));
    }

    do {
        try {
            uint64_t start_time, user, sys, total;
            std::tie(start_time, user, sys, total) =
                    get_proc_time(sigar_pid_t(entry.th32ProcessID));
            allpids[sigar_pid_t(entry.th32ProcessID)] = {
                    sigar_pid_t(entry.th32ProcessID),
                    sigar_pid_t(entry.th32ParentProcessID),
                    std::string(entry.szExeFile),
                    start_time};
        } catch (const std::exception&) {
        }
    } while (Process32Next(snapshotHandle, &entry));

    CloseHandle(snapshotHandle);
    return allpids;
}

bool Win32Sigar::check_parents(
        sigar_pid_t pid,
        sigar_pid_t ppid,
        const std::unordered_map<sigar_pid_t, AllPidInfo>& allprocinfo) {
    std::vector<sigar_pid_t> pids;
    do {
        auto iter = allprocinfo.find(pid);
        if (iter == allprocinfo.end()) {
            return false;
        }

        if (iter->second.ppid == ppid) {
            return true;
        }
        pids.push_back(pid);
        pid = iter->second.ppid;
        if (std::find(pids.begin(), pids.end(), pid) != pids.end()) {
            // There is a loop in the process chain
            return false;
        }
    } while (ppid != 0);
    // not found
    return false;
}

void Win32Sigar::iterate_child_processes(
        sigar_pid_t ppid, sigar::IterateChildProcessCallback callback) {
    const auto allpids = get_all_pids();
    for (const auto& [pid, pinfo] : allpids) {
        if (check_parents(pid, ppid, allpids)) {
            callback(pid, pinfo.ppid, pinfo.start_time, pinfo.name);
        }
    }
}

/*
 * Pretty good explanation of counters:
 * http://www.semack.net/wiki/default.asp?db=SemackNetWiki&o=VirtualMemory
 */
sigar_proc_mem_t Win32Sigar::get_proc_memory(sigar_pid_t pid) {
    sigar_proc_mem_t procmem;
    auto [status, pinfo] = get_proc_info(pid);
    if (status != SIGAR_OK) {
        throw std::system_error(std::error_code(status, std::system_category()),
                                "Win32Sigar::get_proc_memory: get_proc_info");
    }

    procmem.size = pinfo.size; /* "Virtual Bytes" */
    procmem.resident = pinfo.resident; /* "Working Set" */
    procmem.page_faults = pinfo.page_faults;

    return procmem;
}

std::tuple<uint64_t, uint64_t, uint64_t, uint64_t> Win32Sigar::get_proc_time(
        sigar_pid_t pid) {
    auto proc = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, (DWORD)pid);
    if (!proc) {
        throw std::system_error(
                std::error_code(GetLastError(), std::system_category()),
                "Win32Sigar::get_proc_time: OpenProcess");
    }

    FILETIME start_time, exit_time, system_time, user_time;
    int status = ERROR_SUCCESS;

    if (!GetProcessTimes(
                proc, &start_time, &exit_time, &system_time, &user_time)) {
        status = GetLastError();
    }

    CloseHandle(proc);

    if (status != ERROR_SUCCESS) {
        throw std::system_error(std::error_code(status, std::system_category()),
                                "Win32Sigar::get_proc_time: GetProcessTimes");
    }

    uint64_t start = 0;
    if (start_time.dwHighDateTime) {
        start = sigar_FileTimeToTime(&start_time) / 1000;
    }

    return {start,
            NS100_2MSEC(filetime2uint(user_time)),
            NS100_2MSEC(filetime2uint(system_time)),
            NS100_2MSEC(filetime2uint(user_time)) +
                    NS100_2MSEC(filetime2uint(system_time))};
}

sigar_proc_state_t Win32Sigar::get_proc_state(sigar_pid_t pid) {
    sigar_proc_state_t procstate;
    auto [status, pinfo] = get_proc_info(pid);
    if (status != SIGAR_OK) {
        throw std::system_error(std::error_code(status, std::system_category()),
                                "Win32Sigar::get_proc_state: get_proc_info");
    }

    memcpy(procstate.name, pinfo.name, sizeof(procstate.name));
    procstate.ppid = pinfo.ppid;
    procstate.threads = pinfo.threads;

    return procstate;
}

std::pair<int, sigar_win32_pinfo_t> Win32Sigar::get_proc_info(sigar_pid_t pid) {
    auto proc = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, (DWORD)pid);
    if (!proc) {
        std::system_error error(
                std::error_code(GetLastError(), std::system_category()),
                fmt::format("Win32Sigar::get_proc_info({}): "
                            "OpenProcess failed",
                            pid));
        const auto ec = error.code().value();
        if (ec != ERROR_INVALID_PARAMETER && ec != ERROR_ACCESS_DENIED) {
            // ERROR_INVALID_PARAMETER is returned when the process
            // don't exists so we don't want to log that.
            // We shouldn't care about processes we don't have access
            // to (system processes etc)
            // For all other errors we log the error;
            sigar::logit(sigar::loglevel::err, error.what());
        }
        return {SIGAR_NO_SUCH_PROCESS, {}};
    }

    // At this point we know that the process exists

    sigar_win32_pinfo_t pinfo = {};
    pinfo.pid = pid;

    PROCESS_MEMORY_COUNTERS_EX info;
    info.cb = sizeof(info);
    if (GetProcessMemoryInfo(
                proc, (PROCESS_MEMORY_COUNTERS*)&info, sizeof(info))) {
        pinfo.resident = info.WorkingSetSize;
        pinfo.size = info.WorkingSetSize + info.PagefileUsage;
        pinfo.page_faults = info.PageFaultCount;
    } else {
        std::system_error error(
                std::error_code(GetLastError(), std::system_category()),
                fmt::format("Win32Sigar::get_proc_info({}): "
                            "GetProcessMemoryInfo failed",
                            pid));
        sigar::logit(sigar::loglevel::err, error.what());
        pinfo.resident = std::numeric_limits<uint64_t>::max();
        pinfo.size = std::numeric_limits<uint64_t>::max();
        pinfo.page_faults = std::numeric_limits<uint64_t>::max();
    }

    CloseHandle(proc);

    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshotHandle == INVALID_HANDLE_VALUE) {
        std::system_error error(
                std::error_code(GetLastError(), std::system_category()),
                fmt::format("Win32Sigar::get_proc_info({}): "
                            "CreateToolhelp32Snapshot failed",
                            pid));
        pinfo.ppid = 0;
        pinfo.threads = 0;
        strcpy(pinfo.name, "unknown");
        return {SIGAR_OK, pinfo};
    }

    PROCESSENTRY32 entry = {0};
    entry.dwSize = sizeof(entry);

    auto success = true;
    success = Process32First(snapshotHandle, &entry);
    while (success && entry.th32ProcessID != pid) {
        success = Process32Next(snapshotHandle, &entry);
    }
    if (success && entry.th32ProcessID == pid) {
        pinfo.ppid = entry.th32ParentProcessID;
        pinfo.threads = entry.cntThreads;
        std::string name(entry.szExeFile);
        if (name.length() >= sizeof(pinfo.name) - 1) {
            name.resize(sizeof(pinfo.name) - 1);
        }
        strcpy(pinfo.name, name.c_str());
    } else {
        pinfo.ppid = 0;
        pinfo.threads = 0;
        strcpy(pinfo.name, "unknown");
    }
    CloseHandle(snapshotHandle);

    return {SIGAR_OK, pinfo};
}

void Win32Sigar::iterate_threads(sigar::IterateThreadCallback callback) {
    const auto pid = getpid();
    auto snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshotHandle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("CreateToolhelp32Snapshot: failed " +
                                 std::to_string(GetLastError()));
    }

    THREADENTRY32 entry;
    entry.dwSize = sizeof(entry);

    if (!Thread32First(snapshotHandle, &entry)) {
        CloseHandle(snapshotHandle);
        throw std::runtime_error("Thread32First: failed " +
                                 std::to_string(GetLastError()));
    }

    do {
        if (entry.th32OwnerProcessID == pid) {
            auto th = OpenThread(
                    THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
            if (th != INVALID_HANDLE_VALUE) {
                FILETIME start_time, exit_time, system_time, user_time;
                int status = ERROR_SUCCESS;

                if (GetThreadTimes(th,
                                   &start_time,
                                   &exit_time,
                                   &system_time,
                                   &user_time)) {
                    uint64_t user = NS100_2USEC(filetime2uint(user_time));
                    uint64_t sys = NS100_2USEC(filetime2uint(system_time));
                    callback(entry.th32ThreadID, {}, user, sys);
                } else {
                    callback(entry.th32ThreadID,
                             {},
                             std::numeric_limits<uint64_t>::max(),
                             std::numeric_limits<uint64_t>::max());
                }
                CloseHandle(th);
            }
        }
    } while (Thread32Next(snapshotHandle, &entry));

    CloseHandle(snapshotHandle);
}

void Win32Sigar::iterate_disks(sigar::IterateDiskCallback) {
    // The implementation from upstream returned values which
    // was hard to believe was correct.
}
} // namespace sigar
#else
namespace sigar {
std::unique_ptr<SigarIface> NewWin32Sigar() {
    return {};
}
} // namespace sigar
#endif
