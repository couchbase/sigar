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

#include "sigar.h"
#include "sigar_private.h"

#include <windows.h>

#include <lm.h>
#include <process.h>
#include <processthreadsapi.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <fmt/format.h>
#include <system_error>
#include <vector>

#define EPOCH_DELTA 11644473600000000L

struct sigar_win32_pinfo_t {
    sigar_pid_t pid;
    int ppid;
    int priority;
    time_t mtime;
    uint64_t size;
    uint64_t resident;
    char name[SIGAR_PROC_NAME_LEN];
    char state;
    uint64_t handles;
    uint64_t threads;
    uint64_t page_faults;
};

class Win32Sigar : public sigar_t {
public:
    Win32Sigar() : sigar_t() {
        enable_debug_privilege();
    }

    ~Win32Sigar() override {
    }

    int get_memory(sigar_mem_t& mem) override;
    int get_swap(sigar_swap_t& swap) override;
    int get_cpu(sigar_cpu_t& cpu) override;
    int get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem) override;
    int get_proc_state(sigar_pid_t pid, sigar_proc_state_t& procstate) override;
    void iterate_child_processes(
            sigar_pid_t ppid,
            sigar::IterateChildProcessCallback callback) override;

protected:
    int get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime) override;
    static void enable_debug_privilege();
    bool check_parents(
            sigar_pid_t pid,
            sigar_pid_t ppid,
            std::unordered_map<sigar_pid_t, sigar_win32_pinfo_t> allprocinfo);
    std::pair<int, std::vector<sigar_pid_t>> get_all_pids();
    std::pair<int, sigar_win32_pinfo_t> get_proc_info(sigar_pid_t pid);
};

/* 1/100ns units to milliseconds */
#define NS100_2MSEC(t) ((t) / 10000)

#define PERF_VAL_CPU(ix) NS100_2MSEC(PERF_VAL(ix))

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

sigar_t::sigar_t() = default;

sigar_t* sigar_t::New() {
    return new Win32Sigar;
}

int Win32Sigar::get_memory(sigar_mem_t& mem) {
    PERFORMANCE_INFORMATION pe;
    pe.cb = sizeof(pe);
    if (!GetPerformanceInfo(&pe, sizeof(pe))) {
        return GetLastError();
    }

    mem.total = uint64_t(pe.PhysicalTotal) * pe.PageSize;
    mem.free = uint64_t(pe.PhysicalAvailable) * pe.PageSize;
    mem.used = mem.total - mem.free;
    mem.actual_free = mem.free;
    mem.actual_used = mem.used;

    mem_calc_ram(mem);

    return SIGAR_OK;
}

int Win32Sigar::get_swap(sigar_swap_t& swap) {
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);

    if (!GlobalMemoryStatusEx(&memstat)) {
        return GetLastError();
    }

    swap.total = memstat.ullTotalPageFile;
    swap.free = memstat.ullAvailPageFile;
    swap.used = swap.total - swap.free;

    return SIGAR_OK;
}

static uint64_t filetime2uint(const FILETIME& val) {
    ULARGE_INTEGER ularge;
    ularge.u.LowPart = val.dwLowDateTime;
    ularge.u.HighPart = val.dwHighDateTime;
    return ularge.QuadPart;
}

int Win32Sigar::get_cpu(sigar_cpu_t& cpu) {
    FILETIME idle, kernel, user;
    if (!GetSystemTimes(&idle, &kernel, &user)) {
        return GetLastError();
    }
    cpu.idle = NS100_2MSEC(filetime2uint(idle));
    cpu.sys = NS100_2MSEC(filetime2uint(kernel)) - cpu.idle;
    cpu.user = NS100_2MSEC(filetime2uint(user));
    cpu.total = cpu.idle + cpu.user + cpu.sys;

    return SIGAR_OK;
}

std::pair<int, std::vector<sigar_pid_t>> Win32Sigar::get_all_pids() {
    std::vector<sigar_pid_t> allpids;
    DWORD retval;
    DWORD size = 0;
    std::vector<BYTE> buffer;

    do {
        /* re-use the perfbuf */
        if (size == 0) {
            buffer.resize(8192);
        } else {
            buffer.resize(buffer.size() * 2);
        }
        size = buffer.size();

        if (!EnumProcesses((DWORD*)buffer.data(), buffer.size(), &retval)) {
            const auto error_code = GetLastError();
            std::system_error error(
                    std::error_code(error_code, std::system_category()),
                    "Win32Sigar::get_all_pids(): EnumProcesses");
            sigar::logit(sigar::LogLevel::Error, error.what());

            return {int(error_code), {}};
        }
    } while (retval == buffer.size()); // unlikely

    auto* pids = (DWORD*)buffer.data();

    size = retval / sizeof(DWORD);

    for (DWORD i = 0; i < size; i++) {
        DWORD pid = pids[i];
        if (pid == 0) {
            continue; /* dont include the system Idle process */
        }
        allpids.emplace_back(pid);
    }

    return {SIGAR_OK, std::move(allpids)};
}

bool Win32Sigar::check_parents(
        sigar_pid_t pid,
        sigar_pid_t ppid,
        std::unordered_map<sigar_pid_t, sigar_win32_pinfo_t> allprocinfo) {
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
    const auto [ret, allpids] = get_all_pids();
    if (ret == SIGAR_OK) {
        std::unordered_map<sigar_pid_t, sigar_win32_pinfo_t> allprocinfo;
        for (const auto& pid : allpids) {
            auto [st, pinfo] = get_proc_info(pid);
            if (st == SIGAR_OK) {
                allprocinfo[pid] = std::move(pinfo);
            }
        }

        for (const auto& [pid, pinfo] : allprocinfo) {
            if (check_parents(pid, ppid, allprocinfo)) {
                callback(pinfo.pid, pinfo.ppid, pinfo.mtime, pinfo.name);
            }
        }
    }
}

/*
 * Pretty good explanation of counters:
 * http://www.semack.net/wiki/default.asp?db=SemackNetWiki&o=VirtualMemory
 */
int Win32Sigar::get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem) {
    const auto [status, pinfo] = get_proc_info(pid);
    if (status != SIGAR_OK) {
        return status;
    }

    procmem.size = pinfo.size; /* "Virtual Bytes" */
    procmem.resident = pinfo.resident; /* "Working Set" */
    procmem.page_faults = pinfo.page_faults;

    return SIGAR_OK;
}

int Win32Sigar::get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime) {
    auto proc = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, (DWORD)pid);
    if (!proc) {
        return GetLastError();
    }

    FILETIME start_time, exit_time, system_time, user_time;
    int status = ERROR_SUCCESS;

    if (!GetProcessTimes(
                proc, &start_time, &exit_time, &system_time, &user_time)) {
        status = GetLastError();
    }

    CloseHandle(proc);

    if (status != ERROR_SUCCESS) {
        return status;
    }

    if (start_time.dwHighDateTime) {
        proctime.start_time = sigar_FileTimeToTime(&start_time) / 1000;
    } else {
        proctime.start_time = 0;
    }

    proctime.user = NS100_2MSEC(filetime2uint(user_time));
    proctime.sys = NS100_2MSEC(filetime2uint(system_time));
    proctime.total = proctime.user + proctime.sys;

    return SIGAR_OK;
}

int Win32Sigar::get_proc_state(sigar_pid_t pid, sigar_proc_state_t& procstate) {
    const auto [status, pinfo] = get_proc_info(pid);
    if (status != SIGAR_OK) {
        return status;
    }

    memcpy(procstate.name, pinfo.name, sizeof(procstate.name));
    procstate.state = pinfo.state;
    procstate.ppid = pinfo.ppid;
    procstate.priority = pinfo.priority;
    procstate.threads = pinfo.threads;

    return SIGAR_OK;
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
        auto ec = error.code().value();
        if (ec != ERROR_INVALID_PARAMETER && ec != ERROR_ACCESS_DENIED) {
            // ERROR_INVALID_PARAMETER is returned when the process
            // don't exists so we don't want to log that.
            // For all other errors (access permition errors etc)
            // we log the error and return that the process didn't
            // exists
            sigar::logit(sigar::LogLevel::Error, error.what());
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
        sigar::logit(sigar::LogLevel::Error, error.what());
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
        sigar::logit(sigar::LogLevel::Error, error.what());
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
