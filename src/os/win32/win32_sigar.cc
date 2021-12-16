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
#include "sigar_os.h"
#include "sigar_util.h"
#include <shellapi.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <vector>

#include <processthreadsapi.h>
#include <psapi.h>
#include <time.h>
#include <system_error>

#define PERFBUF_SIZE 8192

#define PERF_TITLE_PROC       230
#define PERF_TITLE_SYS_KEY   "2"
#define PERF_TITLE_MEM_KEY   "4"
#define PERF_TITLE_PROC_KEY  "230"
#define PERF_TITLE_CPU_KEY   "238"
#define PERF_TITLE_DISK_KEY  "236"

#define PERF_TITLE_CPU_USER    142
#define PERF_TITLE_CPU_IDLE    1746
#define PERF_TITLE_CPU_SYS     144
#define PERF_TITLE_CPU_IRQ     698

typedef enum {
    PERF_IX_CPU_USER,
    PERF_IX_CPU_IDLE,
    PERF_IX_CPU_SYS,
    PERF_IX_CPU_IRQ,
    PERF_IX_CPU_MAX
} perf_cpu_offsets_t;

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
#define PERF_TITLE_DISK_READ  214 /* Disk Reads/sec */
#define PERF_TITLE_DISK_WRITE 216 /* Disk Writes/sec */
#define PERF_TITLE_DISK_READ_BYTES  220 /* Disk Read Bytes/sec */
#define PERF_TITLE_DISK_WRITE_BYTES 222 /* Disk Write Bytes/sec */
#define PERF_TITLE_DISK_QUEUE 198 /* Current Disk Queue Length */

/*
 * diff is:
 *   ExW      -> ExA
 *   wcounter -> counter
 */
#define MyRegQueryValue() \
        RegQueryValueExA(sigar->handle, \
                         counter_key, NULL, &type, \
                         sigar->perfbuf, \
                         &bytes)

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

typedef struct {
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
} sigar_win32_pinfo_t;

static std::pair<int, sigar_win32_pinfo_t> get_proc_info(sigar_t* sigar,
                                                         sigar_pid_t pid);

static void sigar_strerror_printf(sigar_t *sigar, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    _vsnprintf(sigar->errbuf, sizeof(sigar->errbuf), format, args);
    va_end(args);
}


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

static DWORD perfbuf_init(sigar_t *sigar)
{
    if (!sigar->perfbuf) {
        sigar->perfbuf = (LPBYTE)malloc(PERFBUF_SIZE);
        sigar->perfbuf_size = PERFBUF_SIZE;
    }

    return sigar->perfbuf_size;
}

static DWORD perfbuf_grow(sigar_t *sigar)
{
    sigar->perfbuf_size += PERFBUF_SIZE;

    sigar->perfbuf =
        (LPBYTE)realloc(sigar->perfbuf, sigar->perfbuf_size);

    return sigar->perfbuf_size;
}

static char *get_counter_name(char *key)
{
    if (strEQ(key, PERF_TITLE_MEM_KEY)) {
        return "Memory";
    }
    else if (strEQ(key, PERF_TITLE_PROC_KEY)) {
        return "Process";
    }
    else if (strEQ(key, PERF_TITLE_CPU_KEY)) {
        return "Processor";
    }
    else if (strEQ(key, PERF_TITLE_DISK_KEY)) {
        return "LogicalDisk";
    }
    else {
        return key;
    }
}

static PERF_OBJECT_TYPE *get_perf_object_inst(sigar_t *sigar,
                                              char *counter_key,
                                              DWORD inst, DWORD *err)
{
    DWORD retval, type, bytes;
    WCHAR wcounter_key[MAX_PATH+1];
    PERF_DATA_BLOCK *block;
    PERF_OBJECT_TYPE *object;

    *err = SIGAR_OK;

    bytes = perfbuf_init(sigar);

    while ((retval = MyRegQueryValue()) != ERROR_SUCCESS) {
        if (retval == ERROR_MORE_DATA) {
            bytes = perfbuf_grow(sigar);
        }
        else {
            *err = retval;
            return NULL;
        }
    }

    block = (PERF_DATA_BLOCK *)sigar->perfbuf;
    if (block->NumObjectTypes == 0) {
        counter_key = get_counter_name(counter_key);
        sigar_strerror_printf(sigar, "No %s counters defined (disabled?)",
                              counter_key);
        *err = -1;
        return NULL;
    }
    object = PdhFirstObject(block);

    /*
     * only seen on windows 2003 server when pdh.dll
     * functions are in use by the same process.
     * confucius say what the fuck.
     */
    if (inst && (object->NumInstances == PERF_NO_INSTANCES)) {
        int i;

        for (i=0; i<block->NumObjectTypes; i++) {
            if (object->NumInstances != PERF_NO_INSTANCES) {
                return object;
            }
            object = PdhNextObject(object);
        }
        return NULL;
    }
    else {
        return object;
    }
}

#define get_perf_object(sigar, counter_key, err) \
    get_perf_object_inst(sigar, counter_key, 1, err)

static int get_mem_counters(sigar_t *sigar, sigar_swap_t *swap, sigar_mem_t *mem)
{
    DWORD status;
    PERF_OBJECT_TYPE *object =
        get_perf_object_inst(sigar, PERF_TITLE_MEM_KEY, 0, &status);
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

static void get_sysinfo(sigar_t *sigar)
{
    SYSTEM_INFO sysinfo;

    GetSystemInfo(&sysinfo);

    sigar->pagesize = sysinfo.dwPageSize;
}

static int sigar_enable_privilege(char *name)
{
    int status;
    HANDLE handle;
    TOKEN_PRIVILEGES tok;

    SIGAR_ZERO(&tok);

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
                          &handle))
    {
        return GetLastError();
    }

    if (LookupPrivilegeValue(NULL, name,
                             &tok.Privileges[0].Luid))
    {
        tok.PrivilegeCount = 1;
        tok.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (AdjustTokenPrivileges(handle, FALSE, &tok, 0, NULL, 0)) {
            status = SIGAR_OK;
        }
        else {
            status = GetLastError();
        }
    }
    else {
        status = GetLastError();
    }

    CloseHandle(handle);

    return status;
}

sigar_t::sigar_t() {
    auto result = RegConnectRegistryA("", HKEY_PERFORMANCE_DATA, &handle);
    if (result != ERROR_SUCCESS) {
        throw std::system_error(std::error_code(result, std::system_category()),
                                "sigar_t(): RegConnectRegistryA");
    }

    get_sysinfo(this);

    /* increase process visibility */
    sigar_enable_privilege(SE_DEBUG_NAME);
}

sigar_t* sigar_t::New() {
    return new sigar_t;
}

const char* sigar_os_error_string(sigar_t* sigar, int err) {
    switch (err) {
      case SIGAR_NO_SUCH_PROCESS:
        return "No such process";
    }
    return NULL;
}

SIGAR_DECLARE(int) sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem)
{
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);

    if (!GlobalMemoryStatusEx(&memstat)) {
        return GetLastError();
    }

    mem->total = memstat.ullTotalPhys;
    mem->free  = memstat.ullAvailPhys;
    mem->used = mem->total - mem->free;
    mem->actual_free = mem->free;
    mem->actual_used = mem->used;
    /* set actual_{free,used} */
    get_mem_counters(sigar, NULL, mem);

    sigar_mem_calc_ram(sigar, mem);

    return SIGAR_OK;
}

SIGAR_DECLARE(int) sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap)
{
    MEMORYSTATUSEX memstat;
    memstat.dwLength = sizeof(memstat);

    if (!GlobalMemoryStatusEx(&memstat)) {
        return GetLastError();
    }

    swap->total = memstat.ullTotalPageFile;
    swap->free  = memstat.ullAvailPageFile;
    swap->used = swap->total - swap->free;

    if (get_mem_counters(sigar, swap, NULL) != SIGAR_OK) {
        swap->page_in = SIGAR_FIELD_NOTIMPL;
        swap->page_out = SIGAR_FIELD_NOTIMPL;
    }

    swap->allocstall = SIGAR_FIELD_NOTIMPL;
    swap->allocstall_dma = SIGAR_FIELD_NOTIMPL;
    swap->allocstall_dma32 = SIGAR_FIELD_NOTIMPL;
    swap->allocstall_normal = SIGAR_FIELD_NOTIMPL;
    swap->allocstall_movable = SIGAR_FIELD_NOTIMPL;

    return SIGAR_OK;
}

static uint64_t filetime2uint(const FILETIME* val) {
    ULARGE_INTEGER ularge;
    ularge.u.LowPart = val->dwLowDateTime;
    ularge.u.HighPart = val->dwHighDateTime;
    return ularge.QuadPart;
}

SIGAR_DECLARE(int) sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    FILETIME idle, kernel, user;
    if (!GetSystemTimes(&idle, &kernel, &user)) {
        return GetLastError();
    }
    memset(cpu, 0, sizeof(*cpu));
    cpu->idle = NS100_2MSEC(filetime2uint(&idle));
    cpu->sys = NS100_2MSEC(filetime2uint(&kernel)) - cpu->idle;
    cpu->user = NS100_2MSEC(filetime2uint(&user));
    cpu->total = cpu->idle + cpu->user + cpu->sys;

    return SIGAR_OK;
}

#define PERF_TITLE_UPTIME_KEY 674 /* System Up Time */

#define get_process_object(sigar, err) \
    get_perf_object(sigar, PERF_TITLE_PROC_KEY, err)

int sigar_os_proc_list_get(sigar_t* sigar, sigar_proc_list_t* proclist) {
    DWORD retval, *pids;
    DWORD size = 0, i;

    do {
        /* re-use the perfbuf */
        if (size == 0) {
            size = perfbuf_init(sigar);
        } else {
            size = perfbuf_grow(sigar);
        }

        if (!EnumProcesses(
                    (DWORD*)sigar->perfbuf, sigar->perfbuf_size, &retval)) {
            return GetLastError();
        }
    } while (retval == sigar->perfbuf_size); // unlikely

    pids = (DWORD*)sigar->perfbuf;

    size = retval / sizeof(DWORD);

    for (i = 0; i < size; i++) {
        DWORD pid = pids[i];
        if (pid == 0) {
            continue; /* dont include the system Idle process */
        }
        SIGAR_PROC_LIST_GROW(proclist);
        proclist->data[proclist->number++] = pid;
    }

    return SIGAR_OK;
}

static int sigar_os_check_parents(sigar_t* sigar, sigar_pid_t pid, sigar_pid_t ppid) {
    try {
        std::vector<sigar_pid_t> pids;
        do {
            const auto [status, pinfo] = get_proc_info(sigar, pid);
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

int sigar_os_proc_list_get_children(sigar_t* sigar,
                                    sigar_pid_t ppid,
                                    sigar_proc_list_t* proclist) {
    sigar_proc_list_t allprocs;
    sigar_proc_list_create(&allprocs);

    int ret = sigar_os_proc_list_get(sigar, &allprocs);

    if (ret == SIGAR_OK) {
        for (int i = 0; i < allprocs.number; ++i) {
            sigar_pid_t pid = allprocs.data[i];
            if (sigar_os_check_parents(sigar, pid, ppid) == SIGAR_OK) {
                SIGAR_PROC_LIST_GROW(proclist);
                proclist->data[proclist->number++] = pid;
            }
        }
    }
    sigar_proc_list_destroy(sigar, &allprocs);
    return ret;
}

#define PROCESS_DAC (PROCESS_QUERY_INFORMATION|PROCESS_VM_READ)

static HANDLE open_process(sigar_pid_t pid)
{
    return OpenProcess(PROCESS_DAC, 0, (DWORD)pid);
}

/*
 * Pretty good explanation of counters:
 * http://www.semack.net/wiki/default.asp?db=SemackNetWiki&o=VirtualMemory
 */
SIGAR_DECLARE(int) sigar_proc_mem_get(sigar_t *sigar, sigar_pid_t pid,
                                      sigar_proc_mem_t *procmem)
{
    const auto [status, pinfo] = get_proc_info(sigar, pid);
    if (status != SIGAR_OK) {
        return status;
    }

    procmem->size     = pinfo.size;     /* "Virtual Bytes" */
    procmem->resident = pinfo.resident; /* "Working Set" */
    procmem->share    = SIGAR_FIELD_NOTIMPL;
    procmem->page_faults  = pinfo.page_faults;
    procmem->minor_faults = SIGAR_FIELD_NOTIMPL;
    procmem->major_faults = SIGAR_FIELD_NOTIMPL;

    return SIGAR_OK;
}

#define TOKEN_DAC (STANDARD_RIGHTS_READ | READ_CONTROL | TOKEN_QUERY)

#define FILETIME2MSEC(ft) \
        NS100_2MSEC((((long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime))

int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_time_t *proctime)
{
    HANDLE proc = open_process(pid);
    FILETIME start_time, exit_time, system_time, user_time;
    int status = ERROR_SUCCESS;

    if (!proc) {
        return GetLastError();
    }

    if (!GetProcessTimes(proc,
                         &start_time, &exit_time,
                         &system_time, &user_time))
    {
        status = GetLastError();
    }

    CloseHandle(proc);

    if (status != ERROR_SUCCESS) {
        return status;
    }

    if (start_time.dwHighDateTime) {
        proctime->start_time =
            sigar_FileTimeToTime(&start_time) / 1000;
    }
    else {
        proctime->start_time = 0;
    }

    proctime->user = FILETIME2MSEC(user_time);
    proctime->sys  = FILETIME2MSEC(system_time);
    proctime->total = proctime->user + proctime->sys;

    return SIGAR_OK;
}

SIGAR_DECLARE(int) sigar_proc_state_get(sigar_t *sigar, sigar_pid_t pid,
                                        sigar_proc_state_t *procstate)
{
    const auto [status, pinfo] = get_proc_info(sigar, pid);
    if (status != SIGAR_OK) {
        return status;
    }

    memcpy(procstate->name, pinfo.name, sizeof(procstate->name));
    procstate->state = pinfo.state;
    procstate->ppid = pinfo.ppid;
    procstate->priority = pinfo.priority;
    procstate->nice = SIGAR_FIELD_NOTIMPL;
    procstate->tty =  SIGAR_FIELD_NOTIMPL;
    procstate->threads = pinfo.threads;
    procstate->processor = SIGAR_FIELD_NOTIMPL;

    return SIGAR_OK;
}

static std::pair<int, sigar_win32_pinfo_t> get_proc_info(sigar_t* sigar,
                                                         sigar_pid_t pid) {
    PERF_OBJECT_TYPE *object;
    PERF_INSTANCE_DEFINITION *inst;
    PERF_COUNTER_DEFINITION *counter;
    DWORD i, err;
    DWORD perf_offsets[PERF_IX_MAX];
    sigar_win32_pinfo_t pinfo = {};

    memset(&perf_offsets, 0, sizeof(perf_offsets));
    object = get_process_object(sigar, &err);

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
