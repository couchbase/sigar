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
#include "sigar_pdh.h"
#include "sigar_private.h"

#include <windows.h>

#include <process.h>
#include <processthreadsapi.h>
#include <psapi.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winperf.h>
#include <winreg.h>

#include <assert.h>
#include <errno.h>
#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <system_error>
#include <vector>

#include <fmt/format.h>
#include <platform/platform_thread.h>

#define EPOCH_DELTA 11644473600000000L

/* XXX: support CP_UTF8 ? */
#define SIGAR_W2A(lpw, lpa, chars) \
    (lpa[0] = '\0',                \
     WideCharToMultiByte(CP_ACP, 0, lpw, -1, (LPSTR)lpa, chars, NULL, NULL))

#define sigar_isdigit(c) (isdigit(((unsigned char)(c))))

namespace sigar {
struct sigar_win32_pinfo_t {
    sigar_pid_t pid;
    int ppid;
    uint64_t size;
    uint64_t resident;
    char name[SIGAR_PROC_NAME_LEN];
    uint64_t handles;
    uint64_t threads;
    uint64_t page_faults;
};

struct AllPidInfo {
    sigar_pid_t pid;
    sigar_pid_t ppid;
    std::string name;
    uint64_t start_time;
};

class Win32Sigar : public SigarIface {
public:
    Win32Sigar() : SigarIface() {
        enable_debug_privilege();
    }

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
    static constexpr size_t PERFBUF_SIZE = 8192;

    std::tuple<uint64_t, uint64_t, uint64_t, uint64_t> get_proc_time(
            sigar_pid_t pid) override;
    static void enable_debug_privilege();
    bool check_parents(
            sigar_pid_t pid,
            sigar_pid_t ppid,
            const std::unordered_map<sigar_pid_t, AllPidInfo>& allprocinfo);

    std::unordered_map<sigar_pid_t, AllPidInfo> get_all_pids();
    std::pair<int, sigar_win32_pinfo_t> get_proc_info(sigar_pid_t pid);
    int get_mem_counters(sigar_swap_t* swap, sigar_mem_t* mem);
    PERF_OBJECT_TYPE* do_get_perf_object_inst(HKEY key,
                                              char* counter_key,
                                              DWORD inst,
                                              DWORD* err);
    PERF_OBJECT_TYPE* get_perf_object_inst(char* counter_key,
                                           DWORD inst,
                                           DWORD* err);

    DWORD perfbuf_init() {
        if (perfbuf.empty()) {
            perfbuf.resize(PERFBUF_SIZE);
        }

        return perfbuf.size();
    }

    DWORD perfbuf_grow() {
        perfbuf.resize(perfbuf.size() + PERFBUF_SIZE);
        return perfbuf.size();
    }

    PERF_INSTANCE_DEFINITION* get_disk_instance(DWORD* perf_offsets,
                                                DWORD* num,
                                                DWORD* err);

public:
    std::vector<BYTE> perfbuf;
    bool working_perf_proc_key = true;
};

#define PERF_TITLE_PROC 230
#define PERF_TITLE_MEM_KEY "4"
#define PERF_TITLE_PROC_KEY "230"
#define PERF_TITLE_CPU_KEY "238"
#define PERF_TITLE_DISK_KEY "236"

#define PERF_TITLE_CPUTIME 6
#define PERF_TITLE_PAGE_FAULTS 28
#define PERF_TITLE_MEM_VSIZE 174
#define PERF_TITLE_MEM_SIZE 180
#define PERF_TITLE_THREAD_CNT 680
#define PERF_TITLE_HANDLE_CNT 952
#define PERF_TITLE_PID 784
#define PERF_TITLE_PPID 1410
#define PERF_TITLE_PRIORITY 682
#define PERF_TITLE_START_TIME 684

typedef enum {
    PERF_IX_CPUTIME,
    PERF_IX_PAGE_FAULTS,
    PERF_IX_MEM_VSIZE,
    PERF_IX_MEM_SIZE,
    PERF_IX_THREAD_CNT,
    PERF_IX_HANDLE_CNT,
    PERF_IX_PID,
    PERF_IX_PPID,
    PERF_IX_PRIORITY,
    PERF_IX_START_TIME,
    PERF_IX_MAX
} perf_proc_offsets_t;

typedef enum {
    PERF_IX_DISK_TIME,
    PERF_IX_DISK_READ_TIME,
    PERF_IX_DISK_WRITE_TIME,
    PERF_IX_DISK_READ,
    PERF_IX_DISK_WRITE,
    PERF_IX_DISK_READ_BYTES,
    PERF_IX_DISK_WRITE_BYTES,
    PERF_IX_DISK_QUEUE,
    PERF_IX_DISK_MAX
} perf_disk_offsets_t;

#define PERF_TITLE_DISK_TIME 200 /* % Disk Time */
#define PERF_TITLE_DISK_READ_TIME 202 /* % Disk Read Time */
#define PERF_TITLE_DISK_WRITE_TIME 204 /* % Disk Write Time */
#define PERF_TITLE_DISK_READ 214 /* Disk Reads/sec */
#define PERF_TITLE_DISK_WRITE 216 /* Disk Writes/sec */
#define PERF_TITLE_DISK_READ_BYTES 220 /* Disk Read Bytes/sec */
#define PERF_TITLE_DISK_WRITE_BYTES 222 /* Disk Write Bytes/sec */
#define PERF_TITLE_DISK_QUEUE 198 /* Current Disk Queue Length */

#define PERF_VAL(ix) \
    perf_offsets[ix] ? *((DWORD*)((BYTE*)counter_block + perf_offsets[ix])) : 0

#define PERF_VAL64(ix)                                                         \
    perf_offsets[ix] ? *((uint64_t*)((BYTE*)counter_block + perf_offsets[ix])) \
                     : 0

/* 1/100ns units to milliseconds */
#define NS100_2MSEC(t) ((t) / 10000)
/* 1/100ns units to microseconds */
#define NS100_2USEC(t) ((t) / 10)

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

static int get_counter_error_code(std::string_view key) {
    if (key == PERF_TITLE_MEM_KEY) {
        sigar::logit(sigar::loglevel::err,
                     fmt::format("Win32Sigar::get_counter_error_code({}): "
                                 "SIGAR_NO_MEMORY_COUNTER",
                                 key));
        return SIGAR_NO_MEMORY_COUNTER;
    }
    if (key == PERF_TITLE_PROC_KEY) {
        sigar::logit(sigar::loglevel::err,
                     fmt::format("Win32Sigar::get_counter_error_code({}): "
                                 "SIGAR_NO_PROCESS_COUNTER",
                                 key));
        return SIGAR_NO_PROCESS_COUNTER;
    }
    if (key == PERF_TITLE_CPU_KEY) {
        sigar::logit(sigar::loglevel::err,
                     fmt::format("Win32Sigar::get_counter_error_code({}): "
                                 "SIGAR_NO_PROCESSOR_COUNTER",
                                 key));
        return SIGAR_NO_PROCESSOR_COUNTER;
    }
    if (key == PERF_TITLE_DISK_KEY) {
        sigar::logit(sigar::loglevel::err,
                     fmt::format("Win32Sigar::get_counter_error_code({}): "
                                 "SIGAR_NO_DISK_COUNTER",
                                 key));
        return SIGAR_NO_DISK_COUNTER;
    }

    throw std::invalid_argument(
            fmt::format("get_counter_error_code(): Invalid key: {}", key));
}

PERF_OBJECT_TYPE* Win32Sigar::do_get_perf_object_inst(HKEY handle,
                                                      char* counter_key,
                                                      DWORD inst,
                                                      DWORD* err) {
    *err = SIGAR_OK;

    DWORD retval;
    DWORD type;
    auto bytes = perfbuf_init();
    while ((retval = RegQueryValueEx(handle,
                                     counter_key,
                                     nullptr,
                                     &type,
                                     perfbuf.data(),
                                     &bytes)) != ERROR_SUCCESS) {
        if (retval == ERROR_MORE_DATA) {
            bytes = perfbuf_grow();
        } else {
            std::system_error error(
                    std::error_code(retval, std::system_category()),
                    fmt::format("Win32Sigar::get_perf_object_inst(): "
                                "RegQueryValueEx({})",
                                counter_key));
            sigar::logit(sigar::loglevel::err, error.what());
            *err = retval;
            return NULL;
        }
    }

    auto* block = reinterpret_cast<PERF_DATA_BLOCK*>(perfbuf.data());
    if (bytes < sizeof(PERF_DATA_BLOCK)) {
        const auto message = fmt::format(
                "Win32Sigar::get_perf_object_inst(): returned {} "
                "bytes which is less than PERF_DATA_BLOCK size {}",
                bytes,
                sizeof(PERF_DATA_BLOCK));

        sigar::logit(sigar::loglevel::err, message);
        throw std::runtime_error(std::move(message));
    }

    if (block->Signature[0] != 'P' || block->Signature[1] != 'E' ||
        block->Signature[2] != 'R' || block->Signature[3] != 'F') {
        const auto message = fmt::format(
                "Win32Sigar::get_perf_object_inst(): Signature isn't PERF");
        sigar::logit(sigar::loglevel::err, message);
        throw std::runtime_error(std::move(message));
    }

    if (block->NumObjectTypes == 0) {
        *err = get_counter_error_code(counter_key);
        if (*err == SIGAR_NO_PROCESS_COUNTER) {
            working_perf_proc_key = false;
        }

        return nullptr;
    }
    auto* object = PdhFirstObject(block);

    /*
     * only seen on windows 2003 server when pdh.dll
     * functions are in use by the same process.
     * confucius say what the fuck.
     */
    if (inst && (object->NumInstances == PERF_NO_INSTANCES)) {
        int i;

        for (i = 0; i < block->NumObjectTypes; i++) {
            if (object->NumInstances != PERF_NO_INSTANCES) {
                return object;
            }
            object = PdhNextObject(object);
        }
        return NULL;
    } else {
        return object;
    }
}

PERF_OBJECT_TYPE* Win32Sigar::get_perf_object_inst(char* counter_key,
                                                   DWORD inst,
                                                   DWORD* err) {
    if (!working_perf_proc_key &&
        strcmp(counter_key, PERF_TITLE_PROC_KEY) == 0) {
        *err = SIGAR_NO_PROCESS_COUNTER;
        return nullptr;
    }

    HKEY handle;
    auto result = RegConnectRegistry(nullptr, HKEY_PERFORMANCE_DATA, &handle);
    if (result != ERROR_SUCCESS) {
        throw std::system_error(std::error_code(result, std::system_category()),
                                "get_perf_object_inst(): RegConnectRegistry");
    }

    try {
        auto* ret = do_get_perf_object_inst(handle, counter_key, inst, err);
        RegCloseKey(handle);
        return ret;
    } catch (const std::exception&) {
        RegCloseKey(handle);
        throw;
    }
}

int Win32Sigar::get_mem_counters(sigar_swap_t* swap, sigar_mem_t* mem) {
    DWORD status;
    auto* object = get_perf_object_inst(PERF_TITLE_MEM_KEY, 0, &status);
    PERF_COUNTER_DEFINITION* counter;
    BYTE* data;
    DWORD i;

    if (!object) {
        return status;
    }

    data = (BYTE*)((BYTE*)object + object->DefinitionLength);

    for (i = 0, counter = PdhFirstCounter(object); i < object->NumCounters;
         i++, counter = PdhNextCounter(counter)) {
        DWORD offset = counter->CounterOffset;

        switch (counter->CounterNameTitleIndex) {
        case 48: /* "Pages Output/sec" */
            if (swap)
                swap->page_out = *((DWORD*)(data + offset));
            break;
        case 76: /* "System Cache Resident Bytes" aka file cache */
            if (mem) {
                uint64_t kern = *((DWORD*)(data + offset));
                mem->actual_free = mem->free + kern;
                mem->actual_used = mem->used - kern;
                return SIGAR_OK;
            }
        case 822: /* "Pages Input/sec" */
            if (swap)
                swap->page_in = *((DWORD*)(data + offset));
            break;
        default:
            continue;
        }
    }

    return SIGAR_OK;
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

std::unique_ptr<SigarIface> NewWin32Sigar() {
    return std::make_unique<Win32Sigar>();
}

sigar_mem_t Win32Sigar::get_memory() {
    sigar_mem_t mem;
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);

    if (!GlobalMemoryStatusEx(&memstat)) {
        throw std::system_error(
                std::error_code(GetLastError(), std::system_category()),
                "Win32Sigar::get_memory(): GlobalMemoryStatusEx");
    }

    mem.total = memstat.ullTotalPhys;
    mem.free = memstat.ullAvailPhys;
    mem.used = mem.total - mem.free;
    mem.actual_free = mem.free;
    mem.actual_used = mem.used;
    /* set actual_{free,used} */
    get_mem_counters(nullptr, &mem);

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

    get_mem_counters(&swap, nullptr);

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
    if (!working_perf_proc_key) {
        // This code is used from sigar_port to populate interesting
        // processes; but we can't read any information out of them
        // anyway. Bail out and save us from calling the code to
        // try to look up the processes when we cannot get any details
        // from them.
        sigar::logit(
                sigar::loglevel::debug,
                "Win32Sigar::iterate_child_processes(): Don't try to look up "
                "processes as we cannot get details of the processes anyway");
        return;
    }

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
    const auto [status, pinfo] = get_proc_info(pid);
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
    const auto [status, pinfo] = get_proc_info(pid);
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
    PERF_OBJECT_TYPE* object;
    PERF_INSTANCE_DEFINITION* inst;
    PERF_COUNTER_DEFINITION* counter;
    DWORD i, err;
    DWORD perf_offsets[PERF_IX_MAX];
    sigar_win32_pinfo_t pinfo = {};

    memset(&perf_offsets, 0, sizeof(perf_offsets));
    object = get_perf_object_inst(PERF_TITLE_PROC_KEY, 1, &err);

    if (!object) {
        if (err == SIGAR_NO_PROCESS_COUNTER) {
            auto proc = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, (DWORD)pid);
            if (proc) {
                sigar::logit(sigar::loglevel::debug,
                             fmt::format("Win32Sigar::get_proc_info({}): "
                                         "process found via OpenProcess.",
                                         pid));
                CloseHandle(proc);
                pinfo.pid = pid;
                pinfo.ppid = 1;
                return {SIGAR_OK, pinfo};
            }
        }

        return {int(err), {}};
    }

    pinfo.pid = pid;

    /*
     * note we assume here:
     *  block->NumObjectTypes == 1
     *  object->ObjectNameTitleIndex == PERF_TITLE_PROC
     *
     * which should always be the case.
     */

    for (i = 0, counter = PdhFirstCounter(object); i < object->NumCounters;
         i++, counter = PdhNextCounter(counter)) {
        DWORD offset = counter->CounterOffset;

        switch (counter->CounterNameTitleIndex) {
        case PERF_TITLE_CPUTIME:
            perf_offsets[PERF_IX_CPUTIME] = offset;
            break;
        case PERF_TITLE_PAGE_FAULTS:
            perf_offsets[PERF_IX_PAGE_FAULTS] = offset;
            break;
        case PERF_TITLE_MEM_VSIZE:
            assert(counter->CounterSize >= 8);
            perf_offsets[PERF_IX_MEM_VSIZE] = offset;
            break;
        case PERF_TITLE_MEM_SIZE:
            assert(counter->CounterSize >= 8);
            perf_offsets[PERF_IX_MEM_SIZE] = offset;
            break;
        case PERF_TITLE_THREAD_CNT:
            perf_offsets[PERF_IX_THREAD_CNT] = offset;
            break;
        case PERF_TITLE_HANDLE_CNT:
            perf_offsets[PERF_IX_HANDLE_CNT] = offset;
            break;
        case PERF_TITLE_PID:
            perf_offsets[PERF_IX_PID] = offset;
            break;
        case PERF_TITLE_PPID:
            perf_offsets[PERF_IX_PPID] = offset;
            break;
        case PERF_TITLE_PRIORITY:
            perf_offsets[PERF_IX_PRIORITY] = offset;
            break;
        case PERF_TITLE_START_TIME:
            perf_offsets[PERF_IX_START_TIME] = offset;
            break;
        }
    }

    for (i = 0, inst = PdhFirstInstance(object); i < object->NumInstances;
         i++, inst = PdhNextInstance(inst)) {
        PERF_COUNTER_BLOCK* counter_block = PdhGetCounterBlock(inst);
        sigar_pid_t this_pid = PERF_VAL(PERF_IX_PID);

        if (this_pid != pid) {
            continue;
        }

        SIGAR_W2A(PdhInstanceName(inst), pinfo.name, sizeof(pinfo.name));

        pinfo.size = PERF_VAL64(PERF_IX_MEM_VSIZE);
        pinfo.resident = PERF_VAL64(PERF_IX_MEM_SIZE);
        pinfo.ppid = PERF_VAL(PERF_IX_PPID);
        pinfo.handles = PERF_VAL(PERF_IX_HANDLE_CNT);
        pinfo.threads = PERF_VAL(PERF_IX_THREAD_CNT);
        pinfo.page_faults = PERF_VAL(PERF_IX_PAGE_FAULTS);

        return {SIGAR_OK, pinfo};
    }

    return {SIGAR_NO_SUCH_PROCESS, {}};
}

void Win32Sigar::iterate_threads(sigar::IterateThreadCallback callback) {
    const auto pid = getpid();
    auto snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
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
        // Do we really need to look at the PID given that we asked for
        // a given pid?
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

PERF_INSTANCE_DEFINITION* Win32Sigar::get_disk_instance(DWORD* perf_offsets,
                                                        DWORD* num,
                                                        DWORD* err) {
    PERF_OBJECT_TYPE* object;
    PERF_INSTANCE_DEFINITION* inst;
    PERF_COUNTER_DEFINITION* counter;
    DWORD i, found = 0;

    object = get_perf_object_inst(PERF_TITLE_DISK_KEY, 1, err);

    if (!object) {
        return NULL;
    }

    for (i = 0, counter = PdhFirstCounter(object); i < object->NumCounters;
         i++, counter = PdhNextCounter(counter)) {
        DWORD offset = counter->CounterOffset;

        switch (counter->CounterNameTitleIndex) {
        case PERF_TITLE_DISK_TIME:
            perf_offsets[PERF_IX_DISK_TIME] = offset;
            found = 1;
            break;
        case PERF_TITLE_DISK_READ_TIME:
            perf_offsets[PERF_IX_DISK_READ_TIME] = offset;
            found = 1;
            break;
        case PERF_TITLE_DISK_WRITE_TIME:
            perf_offsets[PERF_IX_DISK_WRITE_TIME] = offset;
            found = 1;
            break;
        case PERF_TITLE_DISK_READ:
            perf_offsets[PERF_IX_DISK_READ] = offset;
            found = 1;
            break;
        case PERF_TITLE_DISK_WRITE:
            perf_offsets[PERF_IX_DISK_WRITE] = offset;
            found = 1;
            break;
        case PERF_TITLE_DISK_READ_BYTES:
            perf_offsets[PERF_IX_DISK_READ_BYTES] = offset;
            found = 1;
            break;
        case PERF_TITLE_DISK_WRITE_BYTES:
            perf_offsets[PERF_IX_DISK_WRITE_BYTES] = offset;
            found = 1;
            break;
        case PERF_TITLE_DISK_QUEUE:
            perf_offsets[PERF_IX_DISK_QUEUE] = offset;
            found = 1;
            break;
        }
    }

    if (!found) {
        *err = ENOENT;
        return NULL;
    }

    if (num) {
        *num = object->NumInstances;
    }
    return PdhFirstInstance(object);
}

void Win32Sigar::iterate_disks(sigar::IterateDiskCallback callback) {
    DWORD i, err;
    PERF_OBJECT_TYPE* object;
    PERF_INSTANCE_DEFINITION* inst;
    PERF_COUNTER_DEFINITION* counter;
    DWORD perf_offsets[PERF_IX_DISK_MAX];

    memset(&perf_offsets, 0, sizeof(perf_offsets));
    object = get_perf_object_inst(PERF_TITLE_DISK_KEY, 1, &err);

    if (!object) {
        return;
    }

    memset(&perf_offsets, 0, sizeof(perf_offsets));
    inst = get_disk_instance((DWORD*)&perf_offsets, 0, &err);

    if (!inst) {
        return;
    }

    for (i = 0, inst = PdhFirstInstance(object); i < object->NumInstances;
         i++, inst = PdhNextInstance(inst)) {
        char drive[MAX_PATH];
        PERF_COUNTER_BLOCK* counter_block = PdhGetCounterBlock(inst);
        wchar_t* name = (wchar_t*)((BYTE*)inst + inst->NameOffset);

        SIGAR_W2A(name, drive, sizeof(drive));

        if (sigar_isdigit(*name)) {
            char* ptr = strchr(drive, ' '); /* 2000 Server "0 C:" */

            if (ptr) {
                ++ptr;
                SIGAR_SSTRCPY(drive, ptr);
            } else {
                /* XXX NT is a number only "0", how to map? */
            }
        }

        sigar::disk_usage_t disk;
        disk.name = drive;

        disk.reads = PERF_VAL(PERF_IX_DISK_READ);
        disk.rbytes = PERF_VAL(PERF_IX_DISK_READ_BYTES);

        disk.writes = PERF_VAL(PERF_IX_DISK_WRITE);
        disk.wbytes = PERF_VAL(PERF_IX_DISK_WRITE_BYTES);

        disk.queue = PERF_VAL(PERF_IX_DISK_QUEUE);

        // Windows has stats for TIME, RTIME, and WTIME, but they appear to
        // be percentages so mapping them to some linux stat implementation
        // is tricky. Skip omitting them here to avoid having some
        // confusingly named stats (given that we care a lot more about linux
        // support).
        callback(disk);
    }
}
} // namespace sigar
#else
namespace sigar {
std::unique_ptr<SigarIface> NewWin32Sigar() {
    return {};
}
} // namespace sigar
#endif
