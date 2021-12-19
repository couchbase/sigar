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
#include "sigar_pdh.h"

#include <windows.h>
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

#define EPOCH_DELTA 11644473600000000L

/* XXX: support CP_UTF8 ? */
#define SIGAR_W2A(lpw, lpa, chars) \
    (lpa[0] = '\0', WideCharToMultiByte(CP_ACP, 0, \
                                        lpw, -1, (LPSTR)lpa, chars, \
                                        NULL, NULL))

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
        auto result = RegConnectRegistryA("", HKEY_PERFORMANCE_DATA, &handle);
        if (result != ERROR_SUCCESS) {
            throw std::system_error(
                    std::error_code(result, std::system_category()),
                    "sigar_t(): RegConnectRegistryA");
        }

        enable_debug_privilege();
    }

    ~Win32Sigar() override {
        RegCloseKey(handle);
    }

    int get_memory(sigar_mem_t& mem) override;
    int get_swap(sigar_swap_t& swap) override;
    int get_cpu(sigar_cpu_t& cpu) override;
    int get_proc_memory(sigar_pid_t pid, sigar_proc_mem_t& procmem) override;
    int get_proc_state(sigar_pid_t pid, sigar_proc_state_t& procstate) override;
    int get_proc_list_children(sigar_pid_t ppid,
                               sigar_proc_list_t* proclist) override;

protected:
    static constexpr size_t PERFBUF_SIZE = 8192;

    int get_proc_time(sigar_pid_t pid, sigar_proc_time_t& proctime) override;
    static void enable_debug_privilege();
    int check_parents(sigar_pid_t pid, sigar_pid_t ppid);
    std::pair<int, std::vector<sigar_pid_t>> get_all_pids();
    std::pair<int, sigar_win32_pinfo_t> get_proc_info(sigar_pid_t pid);
    int get_mem_counters(sigar_swap_t* swap, sigar_mem_t* mem);
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

public:
    HKEY handle;
    std::vector<BYTE> perfbuf;
};

#define PERF_TITLE_PROC       230
#define PERF_TITLE_MEM_KEY   "4"
#define PERF_TITLE_PROC_KEY  "230"
#define PERF_TITLE_CPU_KEY   "238"


#define PERF_TITLE_CPUTIME    6
#define PERF_TITLE_PAGE_FAULTS 28
#define PERF_TITLE_MEM_VSIZE  174
#define PERF_TITLE_MEM_SIZE   180
#define PERF_TITLE_THREAD_CNT 680
#define PERF_TITLE_HANDLE_CNT 952
#define PERF_TITLE_PID        784
#define PERF_TITLE_PPID       1410
#define PERF_TITLE_PRIORITY   682
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

#define PERF_VAL(ix) \
    perf_offsets[ix] ? \
        *((DWORD *)((BYTE *)counter_block + perf_offsets[ix])) : 0

#define PERF_VAL64(ix) \
    perf_offsets[ix] ? \
        *((uint64_t *)((BYTE *)counter_block + perf_offsets[ix])) : 0

/* 1/100ns units to milliseconds */
#define NS100_2MSEC(t) ((t) / 10000)

#define PERF_VAL_CPU(ix) \
    NS100_2MSEC(PERF_VAL(ix))

static uint64_t sigar_FileTimeToTime(FILETIME *ft)
{
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
        return SIGAR_NO_MEMORY_COUNTER;
    } else if (key == PERF_TITLE_PROC_KEY) {
        return SIGAR_NO_PROCESS_COUNTER;
    } else if (key == PERF_TITLE_CPU_KEY) {
        return SIGAR_NO_PROCESSOR_COUNTER;
    }

    throw std::invalid_argument(
            std::string("get_counter_error_code(): Invalid key: ") +
            std::string(key));
}

PERF_OBJECT_TYPE* Win32Sigar::get_perf_object_inst(char* counter_key,
                                                   DWORD inst,
                                                   DWORD* err) {
    *err = SIGAR_OK;

    DWORD retval;
    DWORD type;
    auto bytes = perfbuf_init();
    while ((retval = RegQueryValueExA(handle,
                                      counter_key,
                                      NULL,
                                      &type,
                                      perfbuf.data(),
                                      &bytes)) != ERROR_SUCCESS) {
        if (retval == ERROR_MORE_DATA) {
            bytes = perfbuf_grow();
        } else {
            *err = retval;
            return NULL;
        }
    }

    auto* block = reinterpret_cast<PERF_DATA_BLOCK*>(perfbuf.data());
    if (block->NumObjectTypes == 0) {
        *err = get_counter_error_code(counter_key);
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

int Win32Sigar::get_mem_counters(sigar_swap_t* swap, sigar_mem_t* mem) {
    DWORD status;
    auto* object = get_perf_object_inst(PERF_TITLE_MEM_KEY, 0, &status);
    PERF_COUNTER_DEFINITION *counter;
    BYTE *data;
    DWORD i;

    if (!object) {
        return status;
    }

    data = (BYTE *)((BYTE *)object + object->DefinitionLength);

    for (i=0, counter = PdhFirstCounter(object);
         i<object->NumCounters;
         i++, counter = PdhNextCounter(counter))
    {
        DWORD offset = counter->CounterOffset;

        switch (counter->CounterNameTitleIndex) {
          case 48: /* "Pages Output/sec" */
            if (swap) swap->page_out = *((DWORD *)(data + offset));
            break;
          case 76: /* "System Cache Resident Bytes" aka file cache */
            if (mem) {
                uint64_t kern = *((DWORD *)(data + offset));
                mem->actual_free = mem->free + kern;
                mem->actual_used = mem->used - kern;
                return SIGAR_OK;
            }
          case 822: /* "Pages Input/sec" */
            if (swap) swap->page_in = *((DWORD *)(data + offset));
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

sigar_t::sigar_t() = default;

sigar_t* sigar_t::New() {
    return new Win32Sigar;
}

int Win32Sigar::get_memory(sigar_mem_t& mem) {
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);

    if (!GlobalMemoryStatusEx(&memstat)) {
        return GetLastError();
    }

    mem.total = memstat.ullTotalPhys;
    mem.free = memstat.ullAvailPhys;
    mem.used = mem.total - mem.free;
    mem.actual_free = mem.free;
    mem.actual_used = mem.used;
    /* set actual_{free,used} */
    get_mem_counters(nullptr, &mem);

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

    get_mem_counters(&swap, nullptr);

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

    do {
        /* re-use the perfbuf */
        if (size == 0) {
            size = perfbuf_init();
        } else {
            size = perfbuf_grow();
        }

        if (!EnumProcesses((DWORD*)perfbuf.data(), perfbuf.size(), &retval)) {
            return {int(GetLastError()),{}};
        }
    } while (retval == perfbuf.size()); // unlikely

    auto* pids = (DWORD*)perfbuf.data();

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

int Win32Sigar::check_parents(sigar_pid_t pid, sigar_pid_t ppid) {
    try {
        std::vector<sigar_pid_t> pids;
        do {
            const auto [status, pinfo] = get_proc_info(pid);
            if (status != SIGAR_OK) {
                return -1;
            }

            if (pinfo.ppid == ppid) {
                return SIGAR_OK;
            }
            pids.push_back(pid);
            pid = pinfo.ppid;
            if (std::find(pids.begin(), pids.end(), pid) != pids.end()) {
                // There is a loop in the process chain
                return -1;
            }
        } while (ppid != 0);
    } catch (const std::bad_alloc&) {
        return -1;
    }
    // not found
    return -1;
}

int Win32Sigar::get_proc_list_children(sigar_pid_t ppid,
                                       sigar_proc_list_t* proclist) {
    const auto [ret, allpids] = get_all_pids();
    if (ret == SIGAR_OK) {
        for (const auto& pid : allpids) {
            if (check_parents(pid, ppid) == SIGAR_OK) {
                SIGAR_PROC_LIST_GROW(proclist);
                proclist->data[proclist->number++] = pid;
            }
        }
    }
    return ret;
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
    PERF_OBJECT_TYPE *object;
    PERF_INSTANCE_DEFINITION *inst;
    PERF_COUNTER_DEFINITION *counter;
    DWORD i, err;
    DWORD perf_offsets[PERF_IX_MAX];
    sigar_win32_pinfo_t pinfo = {};

    memset(&perf_offsets, 0, sizeof(perf_offsets));
    object = get_perf_object_inst(PERF_TITLE_PROC_KEY, 1, &err);

    if (object == NULL) {
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

    for (i=0, counter = PdhFirstCounter(object);
         i<object->NumCounters;
         i++, counter = PdhNextCounter(counter))
    {
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

    for (i=0, inst = PdhFirstInstance(object);
         i<object->NumInstances;
         i++, inst = PdhNextInstance(inst))
    {
        PERF_COUNTER_BLOCK *counter_block = PdhGetCounterBlock(inst);
        sigar_pid_t this_pid = PERF_VAL(PERF_IX_PID);

        if (this_pid != pid) {
            continue;
        }

        pinfo.state = 'R'; /* XXX? */
        SIGAR_W2A(PdhInstanceName(inst),
                  pinfo.name, sizeof(pinfo.name));

        pinfo.size     = PERF_VAL64(PERF_IX_MEM_VSIZE);
        pinfo.resident = PERF_VAL64(PERF_IX_MEM_SIZE);
        pinfo.ppid     = PERF_VAL(PERF_IX_PPID);
        pinfo.priority = PERF_VAL(PERF_IX_PRIORITY);
        pinfo.handles  = PERF_VAL(PERF_IX_HANDLE_CNT);
        pinfo.threads  = PERF_VAL(PERF_IX_THREAD_CNT);
        pinfo.page_faults = PERF_VAL(PERF_IX_PAGE_FAULTS);

        return {SIGAR_OK, pinfo};
    }

    return {SIGAR_NO_SUCH_PROCESS, {}};
}
