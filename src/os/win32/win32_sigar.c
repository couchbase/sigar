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
#include "sigar_format.h"
#include <shellapi.h>
#include <assert.h>

#define USING_WIDE_S(s) (s)->using_wide
#define USING_WIDE()    USING_WIDE_S(sigar)

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
    (USING_WIDE() ? \
        RegQueryValueExW(sigar->handle, \
                         wcounter_key, NULL, &type, \
                         sigar->perfbuf, \
                         &bytes) : \
        RegQueryValueExA(sigar->handle, \
                         counter_key, NULL, &type, \
                         sigar->perfbuf, \
                         &bytes))

#define PERF_VAL(ix) \
    perf_offsets[ix] ? \
        *((DWORD *)((BYTE *)counter_block + perf_offsets[ix])) : 0

#define PERF_VAL64(ix) \
    perf_offsets[ix] ? \
        *((sigar_uint64_t *)((BYTE *)counter_block + perf_offsets[ix])) : 0

/* 1/100ns units to milliseconds */
#define NS100_2MSEC(t) ((t) / 10000)

#define PERF_VAL_CPU(ix) \
    NS100_2MSEC(PERF_VAL(ix))

#define MS_LOOPBACK_ADAPTER "Microsoft Loopback Adapter"
#define NETIF_LA "la"

sigar_uint64_t sigar_FileTimeToTime(FILETIME *ft)
{
    sigar_uint64_t time;
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
        sigar->perfbuf = malloc(PERFBUF_SIZE);
        sigar->perfbuf_size = PERFBUF_SIZE;
    }

    return sigar->perfbuf_size;
}

static DWORD perfbuf_grow(sigar_t *sigar)
{
    sigar->perfbuf_size += PERFBUF_SIZE;

    sigar->perfbuf =
        realloc(sigar->perfbuf, sigar->perfbuf_size);

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

    if (USING_WIDE()) {
        SIGAR_A2W(counter_key, wcounter_key, sizeof(wcounter_key));
    }

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
                sigar_uint64_t kern = *((DWORD *)(data + offset));
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

    sigar->ncpu = sysinfo.dwNumberOfProcessors;
    sigar->pagesize = sysinfo.dwPageSize;
}

/* for C# bindings */
SIGAR_DECLARE(sigar_t *) sigar_new(void)
{
    sigar_t *sigar;
    if (sigar_open(&sigar) != SIGAR_OK) {
        return NULL;
    }
    return sigar;
}

static sigar_wtsapi_t sigar_wtsapi = {
    "wtsapi32.dll",
    NULL,
    { "WTSEnumerateSessionsA", NULL },
    { "WTSFreeMemory", NULL },
    { "WTSQuerySessionInformationA", NULL },
    { NULL, NULL }
};

static sigar_iphlpapi_t sigar_iphlpapi = {
    "iphlpapi.dll",
    NULL,
    { "GetIpForwardTable", NULL },
    { "GetIpAddrTable", NULL },
    { "GetIfTable", NULL },
    { "GetIfEntry", NULL },
    { "GetNumberOfInterfaces", NULL },
    { "GetTcpTable", NULL },
    { "GetUdpTable", NULL },
    { "AllocateAndGetTcpExTableFromStack", NULL },
    { "AllocateAndGetUdpExTableFromStack", NULL },
    { "GetTcpStatistics", NULL },
    { "GetNetworkParams", NULL },
    { "GetAdaptersInfo", NULL },
    { "GetAdaptersAddresses", NULL },
    { "GetIpNetTable", NULL },
    { NULL, NULL }
};

static sigar_advapi_t sigar_advapi = {
    "advapi32.dll",
    NULL,
    { "ConvertStringSidToSidA", NULL },
    { "QueryServiceStatusEx", NULL },
    { NULL, NULL }
};

static sigar_ntdll_t sigar_ntdll = {
    "ntdll.dll",
    NULL,
    { "NtQuerySystemInformation", NULL },
    { "NtQueryInformationProcess", NULL },
    { NULL, NULL }
};

static sigar_psapi_t sigar_psapi = {
    "psapi.dll",
    NULL,
    { "EnumProcessModules", NULL },
    { "EnumProcesses", NULL },
    { "GetModuleFileNameExA", NULL },
    { NULL, NULL }
};

static sigar_psapi_t sigar_winsta = {
    "winsta.dll",
    NULL,
    { "WinStationQueryInformationW", NULL },
    { NULL, NULL }
};

static sigar_psapi_t sigar_kernel = {
    "kernel32.dll",
    NULL,
    { "GlobalMemoryStatusEx", NULL },
    { NULL, NULL }
};

static sigar_mpr_t sigar_mpr = {
    "mpr.dll",
    NULL,
    { "WNetGetConnectionA", NULL },
    { NULL, NULL }
};

#define DLLMOD_COPY(name) \
    memcpy(&(sigar->name), &sigar_##name, sizeof(sigar_##name))

#define DLLMOD_INIT(name, all) \
    sigar_dllmod_init(sigar, (sigar_dll_module_t *)&(sigar->name), all)

#define DLLMOD_FREE(name) \
    sigar_dllmod_free((sigar_dll_module_t *)&(sigar->name))

static void sigar_dllmod_free(sigar_dll_module_t *module)
{
    if (module->handle) {
        FreeLibrary(module->handle);
        module->handle = NULL;
    }
}

static int sigar_dllmod_init(sigar_t *sigar,
                             sigar_dll_module_t *module,
                             int all)
{
    sigar_dll_func_t *funcs = &module->funcs[0];
    int is_debug = SIGAR_LOG_IS_DEBUG(sigar);
    int rc, success;

    if (module->handle == INVALID_HANDLE_VALUE) {
        return ENOENT; /* XXX better rc */
    }

    if (module->handle) {
        return SIGAR_OK;
    }

    module->handle = LoadLibrary(module->name);
    if (!(success = (module->handle ? TRUE : FALSE))) {
        rc = GetLastError();
        /* dont try again */
        module->handle = INVALID_HANDLE_VALUE;
    }

    if (is_debug) {
        sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                         "LoadLibrary(%s): %s",
                         module->name,
                         success ?
                         "OK" :
                         sigar_strerror(sigar, rc));
    }

    if (!success) {
        return rc;
    }

    while (funcs->name) {
        funcs->func = GetProcAddress(module->handle, funcs->name);

        if (!(success = (funcs->func ? TRUE : FALSE))) {
            rc = GetLastError();
        }

        if (is_debug) {
            sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                             "GetProcAddress(%s:%s): %s",
                             module->name, funcs->name,
                             success ?
                             "OK" :
                             sigar_strerror(sigar, rc));
        }

        if (all && !success) {
            return rc;
        }

        funcs++;
    }

    return SIGAR_OK;
}

int sigar_wsa_init(sigar_t *sigar)
{
    if (sigar->ws_version == 0) {
        WSADATA data;

        if (WSAStartup(MAKEWORD(2, 0), &data)) {
            sigar->ws_error = WSAGetLastError();
            WSACleanup();
            return sigar->ws_error;
        }

        sigar->ws_version = data.wVersion;
    }

    return SIGAR_OK;
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

int sigar_os_open(sigar_t **sigar_ptr)
{
    LONG result;
    OSVERSIONINFO version;
    sigar_t *sigar;

    *sigar_ptr = sigar = malloc(sizeof(*sigar));
    sigar->machine = ""; /* local machine */
    sigar->using_wide = 0; /*XXX*/

    sigar->perfbuf = NULL;
    sigar->perfbuf_size = 0;

    version.dwOSVersionInfoSize = sizeof(version);
    GetVersionEx(&version);

    /*
     * 4 == NT 4.0
     * 5 == 2000, XP, 2003 Server
     */
    sigar->winnt = (version.dwMajorVersion == 4);

    if (USING_WIDE_S(sigar)) {
        WCHAR wmachine[MAX_PATH+1];

        SIGAR_A2W(sigar->machine, wmachine, sizeof(wmachine));

        result = RegConnectRegistryW(wmachine,
                                     HKEY_PERFORMANCE_DATA,
                                     &sigar->handle);
    }
    else {
        result = RegConnectRegistryA(sigar->machine,
                                     HKEY_PERFORMANCE_DATA,
                                     &sigar->handle);
    }

    get_sysinfo(sigar);

    DLLMOD_COPY(wtsapi);
    DLLMOD_COPY(iphlpapi);
    DLLMOD_COPY(advapi);
    DLLMOD_COPY(ntdll);
    DLLMOD_COPY(psapi);
    DLLMOD_COPY(winsta);
    DLLMOD_COPY(kernel);
    DLLMOD_COPY(mpr);

    sigar->log_level = -1; /* else below segfaults */
    /* XXX init early for use by javasigar.c */
    sigar_dllmod_init(sigar,
                      (sigar_dll_module_t *)&sigar->advapi,
                      FALSE);

    sigar->netif_mib_rows = NULL;
    sigar->netif_addr_rows = NULL;
    sigar->netif_adapters = NULL;
    sigar->netif_names = NULL;
    sigar->pinfo.pid = -1;
    sigar->ws_version = 0;
    sigar->lcpu = -1;

    /* increase process visibility */
    sigar_enable_privilege(SE_DEBUG_NAME);

    return result;
}

void dllmod_init_ntdll(sigar_t *sigar)
{
    DLLMOD_INIT(ntdll, FALSE);
}

int sigar_os_close(sigar_t *sigar)
{
    int retval;

    DLLMOD_FREE(wtsapi);
    DLLMOD_FREE(iphlpapi);
    DLLMOD_FREE(advapi);
    DLLMOD_FREE(ntdll);
    DLLMOD_FREE(psapi);
    DLLMOD_FREE(winsta);
    DLLMOD_FREE(kernel);
    DLLMOD_FREE(mpr);

    if (sigar->perfbuf) {
        free(sigar->perfbuf);
    }

    retval = RegCloseKey(sigar->handle);

    if (sigar->ws_version != 0) {
        WSACleanup();
    }

    if (sigar->netif_mib_rows) {
        sigar_cache_destroy(sigar->netif_mib_rows);
    }

    if (sigar->netif_addr_rows) {
        sigar_cache_destroy(sigar->netif_addr_rows);
    }

    if (sigar->netif_adapters) {
        sigar_cache_destroy(sigar->netif_adapters);
    }

    if (sigar->netif_names) {
        sigar_cache_destroy(sigar->netif_names);
    }

    free(sigar);

    return retval;
}

char *sigar_os_error_string(sigar_t *sigar, int err)
{
    switch (err) {
      case SIGAR_NO_SUCH_PROCESS:
        return "No such process";
        break;
    }
    return NULL;
}

#define sigar_GlobalMemoryStatusEx \
    sigar->kernel.memory_status.func

SIGAR_DECLARE(int) sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem)
{
    DLLMOD_INIT(kernel, TRUE);

    if (sigar_GlobalMemoryStatusEx) {
        MEMORYSTATUSEX memstat;

        memstat.dwLength = sizeof(memstat);

        if (!sigar_GlobalMemoryStatusEx(&memstat)) {
            return GetLastError();
        }

        mem->total = memstat.ullTotalPhys;
        mem->free  = memstat.ullAvailPhys;
    }
    else {
        MEMORYSTATUS memstat;
        GlobalMemoryStatus(&memstat);
        mem->total = memstat.dwTotalPhys;
        mem->free  = memstat.dwAvailPhys;
    }

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
    DLLMOD_INIT(kernel, TRUE);

    if (sigar_GlobalMemoryStatusEx) {
        MEMORYSTATUSEX memstat;

        memstat.dwLength = sizeof(memstat);

        if (!sigar_GlobalMemoryStatusEx(&memstat)) {
            return GetLastError();
        }

        swap->total = memstat.ullTotalPageFile;
        swap->free  = memstat.ullAvailPageFile;
    }
    else {
        MEMORYSTATUS memstat;
        GlobalMemoryStatus(&memstat);
        swap->total = memstat.dwTotalPageFile;
        swap->free  = memstat.dwAvailPageFile;
    }

    swap->used = swap->total - swap->free;

    if (get_mem_counters(sigar, swap, NULL) != SIGAR_OK) {
        swap->page_in = SIGAR_FIELD_NOTIMPL;
        swap->page_out = SIGAR_FIELD_NOTIMPL;
    }

    swap->allocstall = -1;
    swap->allocstall_dma = -1;
    swap->allocstall_dma32 = -1;
    swap->allocstall_normal = -1;
    swap->allocstall_movable = -1;

    return SIGAR_OK;
}

static PERF_INSTANCE_DEFINITION *get_cpu_instance(sigar_t *sigar,
                                                  DWORD *perf_offsets,
                                                  DWORD *num, DWORD *err)
{
    PERF_OBJECT_TYPE *object = get_perf_object(sigar, PERF_TITLE_CPU_KEY, err);
    PERF_COUNTER_DEFINITION *counter;
    DWORD i;

    if (!object) {
        return NULL;
    }

    for (i=0, counter = PdhFirstCounter(object);
         i<object->NumCounters;
         i++, counter = PdhNextCounter(counter))
    {
        DWORD offset = counter->CounterOffset;

        switch (counter->CounterNameTitleIndex) {
          case PERF_TITLE_CPU_SYS:
            perf_offsets[PERF_IX_CPU_SYS] = offset;
            break;
          case PERF_TITLE_CPU_USER:
            perf_offsets[PERF_IX_CPU_USER] = offset;
            break;
          case PERF_TITLE_CPU_IDLE:
            perf_offsets[PERF_IX_CPU_IDLE] = offset;
            break;
          case PERF_TITLE_CPU_IRQ:
            perf_offsets[PERF_IX_CPU_IRQ] = offset;
            break;
        }
    }

    if (num) {
        *num = object->NumInstances;
    }

    return PdhFirstInstance(object);
}

#define SPPI_MAX 128 /* XXX unhardcode; should move off this api anyhow */

#define sigar_NtQuerySystemInformation \
   sigar->ntdll.query_sys_info.func

static int get_idle_cpu(sigar_t *sigar, sigar_cpu_t *cpu,
                        DWORD idx,
                        PERF_COUNTER_BLOCK *counter_block,
                        DWORD *perf_offsets)
{
    cpu->idle = 0;

    if (perf_offsets[PERF_IX_CPU_IDLE]) {
        cpu->idle = PERF_VAL_CPU(PERF_IX_CPU_IDLE);
    }
    else {
        /* windows NT and 2000 do not have an Idle counter */
        DLLMOD_INIT(ntdll, FALSE);
        if (sigar_NtQuerySystemInformation) {
            DWORD retval, num;
            SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION info[SPPI_MAX];
            /* into the lungs of hell */
            sigar_NtQuerySystemInformation(SystemProcessorPerformanceInformation,
                                           &info, sizeof(info), &retval);

            if (!retval) {
                return GetLastError();
            }
            num = retval/sizeof(info[0]);

            if (idx == -1) {
                int i;
                for (i=0; i<num; i++) {
                    cpu->idle += NS100_2MSEC(info[i].IdleTime.QuadPart);
                }
            }
            else if (idx < num) {
                cpu->idle = NS100_2MSEC(info[idx].IdleTime.QuadPart);
            }
            else {
                return ERROR_INVALID_DATA;
            }
        }
        else {
            return ERROR_INVALID_FUNCTION;
        }
    }

    return SIGAR_OK;
}

static int sigar_cpu_perflib_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    int status;
    PERF_INSTANCE_DEFINITION *inst;
    PERF_COUNTER_BLOCK *counter_block;
    DWORD perf_offsets[PERF_IX_CPU_MAX], err;

    SIGAR_ZERO(cpu);
    memset(&perf_offsets, 0, sizeof(perf_offsets));

    inst = get_cpu_instance(sigar, (DWORD*)&perf_offsets, 0, &err);

    if (!inst) {
        return err;
    }

    /* first instance is total, rest are per-cpu */
    counter_block = PdhGetCounterBlock(inst);

    cpu->sys  = PERF_VAL_CPU(PERF_IX_CPU_SYS);
    cpu->user = PERF_VAL_CPU(PERF_IX_CPU_USER);
    status = get_idle_cpu(sigar, cpu, -1, counter_block, perf_offsets);
    cpu->irq = PERF_VAL_CPU(PERF_IX_CPU_IRQ);
    cpu->nice = 0; /* no nice here */
    cpu->wait = 0; /*N/A?*/
    cpu->total = cpu->sys + cpu->user + cpu->idle + cpu->wait + cpu->irq;

    if (status != SIGAR_OK) {
        sigar_log_printf(sigar, SIGAR_LOG_WARN,
                         "unable to determine idle cpu time: %s",
                         sigar_strerror(sigar, status));
    }

    return SIGAR_OK;
}

static int sigar_cpu_ntsys_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    DWORD retval, num;
    int i;
    SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION info[SPPI_MAX];
    /* into the lungs of hell */
    sigar_NtQuerySystemInformation(SystemProcessorPerformanceInformation,
                                   &info, sizeof(info), &retval);

    if (!retval) {
        return GetLastError();
    }
    num = retval/sizeof(info[0]);
    SIGAR_ZERO(cpu);

    for (i=0; i<num; i++) {
        cpu->idle += NS100_2MSEC(info[i].IdleTime.QuadPart);
        cpu->user += NS100_2MSEC(info[i].UserTime.QuadPart);
        cpu->sys  += NS100_2MSEC(info[i].KernelTime.QuadPart -
                                 info[i].IdleTime.QuadPart);
        cpu->irq  += NS100_2MSEC(info[i].InterruptTime.QuadPart);
    }
    cpu->total = cpu->idle + cpu->user + cpu->sys;

    return SIGAR_OK;
}

SIGAR_DECLARE(int) sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    DLLMOD_INIT(ntdll, FALSE);
    if (sigar_NtQuerySystemInformation) {
        return sigar_cpu_ntsys_get(sigar, cpu);
    }
    else {
        return sigar_cpu_perflib_get(sigar, cpu);
    }
}


#define PERF_TITLE_UPTIME_KEY 674 /* System Up Time */


#define get_process_object(sigar, err) \
    get_perf_object(sigar, PERF_TITLE_PROC_KEY, err)

static int sigar_proc_list_get_perf(sigar_t *sigar,
                                    sigar_proc_list_t *proclist)
{

    PERF_OBJECT_TYPE *object;
    PERF_INSTANCE_DEFINITION *inst;
    PERF_COUNTER_DEFINITION *counter;
    DWORD i, err;
    DWORD perf_offsets[PERF_IX_MAX];

    perf_offsets[PERF_IX_PID] = 0;

    object = get_process_object(sigar, &err);

    if (!object) {
        return err;
    }

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
          case PERF_TITLE_PID:
            perf_offsets[PERF_IX_PID] = offset;
            break;
        }
    }

    for (i=0, inst = PdhFirstInstance(object);
         i<object->NumInstances;
         i++, inst = PdhNextInstance(inst))
    {
        PERF_COUNTER_BLOCK *counter_block = PdhGetCounterBlock(inst);
        DWORD pid = PERF_VAL(PERF_IX_PID);

        if (pid == 0) {
            continue; /* dont include the system Idle process */
        }

        SIGAR_PROC_LIST_GROW(proclist);

        proclist->data[proclist->number++] = pid;
    }

    return SIGAR_OK;
}

#define sigar_EnumProcesses \
    sigar->psapi.enum_processes.func

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist)
{
    DLLMOD_INIT(psapi, FALSE);

    if (sigar_EnumProcesses) {
        DWORD retval, *pids;
        DWORD size = 0, i;

        do {
            /* re-use the perfbuf */
            if (size == 0) {
                size = perfbuf_init(sigar);
            }
            else {
                size = perfbuf_grow(sigar);
            }

            if (!sigar_EnumProcesses((DWORD *)sigar->perfbuf,
                                     sigar->perfbuf_size,
                                     &retval))
            {
                return GetLastError();
            }
        } while (retval == sigar->perfbuf_size); //unlikely

        pids = (DWORD *)sigar->perfbuf;

        size = retval / sizeof(DWORD);

        for (i=0; i<size; i++) {
            DWORD pid = pids[i];
            if (pid == 0) {
                continue; /* dont include the system Idle process */
            }
            SIGAR_PROC_LIST_GROW(proclist);
            proclist->data[proclist->number++] = pid;
        }

        return SIGAR_OK;
    }
    else {
        return sigar_proc_list_get_perf(sigar, proclist);
    }
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
    int status = get_proc_info(sigar, pid);
    sigar_win32_pinfo_t *pinfo = &sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    procmem->size     = pinfo->size;     /* "Virtual Bytes" */
    procmem->resident = pinfo->resident; /* "Working Set" */
    procmem->share    = SIGAR_FIELD_NOTIMPL;
    procmem->page_faults  = pinfo->page_faults;
    procmem->minor_faults = SIGAR_FIELD_NOTIMPL;
    procmem->major_faults = SIGAR_FIELD_NOTIMPL;

    return SIGAR_OK;
}

#define TOKEN_DAC (STANDARD_RIGHTS_READ | READ_CONTROL | TOKEN_QUERY)

#define FILETIME2MSEC(ft) \
        NS100_2MSEC((((long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime))

sigar_int64_t sigar_time_now_millis(void)
{
    SYSTEMTIME st;
    FILETIME time;

    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &time);

    return sigar_FileTimeToTime(&time) / 1000;
}

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
    int status = get_proc_info(sigar, pid);
    sigar_win32_pinfo_t *pinfo = &sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    memcpy(procstate->name, pinfo->name, sizeof(procstate->name));
    procstate->state = pinfo->state;
    procstate->ppid = pinfo->ppid;
    procstate->priority = pinfo->priority;
    procstate->nice = SIGAR_FIELD_NOTIMPL;
    procstate->tty =  SIGAR_FIELD_NOTIMPL;
    procstate->threads = pinfo->threads;
    procstate->processor = SIGAR_FIELD_NOTIMPL;

    return SIGAR_OK;
}

int get_proc_info(sigar_t *sigar, sigar_pid_t pid)
{
    PERF_OBJECT_TYPE *object;
    PERF_INSTANCE_DEFINITION *inst;
    PERF_COUNTER_DEFINITION *counter;
    DWORD i, err;
    DWORD perf_offsets[PERF_IX_MAX];
    sigar_win32_pinfo_t *pinfo = &sigar->pinfo;
    time_t timenow = time(NULL);

    if (pinfo->pid == pid) {
        if ((timenow - pinfo->mtime) < SIGAR_LAST_PROC_EXPIRE) {
            return SIGAR_OK;
        }
    }

    memset(&perf_offsets, 0, sizeof(perf_offsets));

    object = get_process_object(sigar, &err);

    if (object == NULL) {
        return err;
    }

    pinfo->pid = pid;
    pinfo->mtime = timenow;

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

        pinfo->state = 'R'; /* XXX? */
        SIGAR_W2A(PdhInstanceName(inst),
                  pinfo->name, sizeof(pinfo->name));

        pinfo->size     = PERF_VAL64(PERF_IX_MEM_VSIZE);
        pinfo->resident = PERF_VAL64(PERF_IX_MEM_SIZE);
        pinfo->ppid     = PERF_VAL(PERF_IX_PPID);
        pinfo->priority = PERF_VAL(PERF_IX_PRIORITY);
        pinfo->handles  = PERF_VAL(PERF_IX_HANDLE_CNT);
        pinfo->threads  = PERF_VAL(PERF_IX_THREAD_CNT);
        pinfo->page_faults = PERF_VAL(PERF_IX_PAGE_FAULTS);

        return SIGAR_OK;
    }

    return SIGAR_NO_SUCH_PROCESS;
}

int sigar_os_fs_type_get(sigar_file_system_t *fsp)
{
    return fsp->type;
}

#ifndef FILE_READ_ONLY_VOLUME
#define FILE_READ_ONLY_VOLUME 0x00080000
#endif
#ifndef FILE_NAMED_STREAMS
#define FILE_NAMED_STREAMS 0x00040000
#endif
#ifndef FILE_SEQUENTIAL_WRITE_ONCE
#define FILE_SEQUENTIAL_WRITE_ONCE 0x00100000
#endif
#ifndef FILE_SUPPORTS_TRANSACTIONS
#define FILE_SUPPORTS_TRANSACTIONS 0x00200000
#endif

static void get_fs_options(char *opts, int osize, long flags)
{
    *opts = '\0';
    if (flags & FILE_READ_ONLY_VOLUME)        strncat(opts, "ro", osize);
    else                                      strncat(opts, "rw", osize);
#if 0 /*XXX*/
    if (flags & FILE_CASE_PRESERVED_NAMES)    strncat(opts, ",casepn", osize);
    if (flags & FILE_CASE_SENSITIVE_SEARCH)   strncat(opts, ",casess", osize);
    if (flags & FILE_FILE_COMPRESSION)        strncat(opts, ",fcomp", osize);
    if (flags & FILE_NAMED_STREAMS)           strncat(opts, ",streams", osize);
    if (flags & FILE_PERSISTENT_ACLS)         strncat(opts, ",acls", osize);
    if (flags & FILE_SEQUENTIAL_WRITE_ONCE)   strncat(opts, ",wronce", osize);
    if (flags & FILE_SUPPORTS_ENCRYPTION)     strncat(opts, ",efs", osize);
    if (flags & FILE_SUPPORTS_OBJECT_IDS)     strncat(opts, ",oids", osize);
    if (flags & FILE_SUPPORTS_REPARSE_POINTS) strncat(opts, ",reparse", osize);
    if (flags & FILE_SUPPORTS_SPARSE_FILES)   strncat(opts, ",sparse", osize);
    if (flags & FILE_SUPPORTS_TRANSACTIONS)   strncat(opts, ",trans", osize);
    if (flags & FILE_UNICODE_ON_DISK)         strncat(opts, ",unicode", osize);
    if (flags & FILE_VOLUME_IS_COMPRESSED)    strncat(opts, ",vcomp", osize);
    if (flags & FILE_VOLUME_QUOTAS)           strncat(opts, ",quota", osize);
#endif
}

#define sigar_WNetGetConnection \
    sigar->mpr.get_net_connection.func

SIGAR_DECLARE(int) sigar_file_system_list_get(sigar_t *sigar,
                                              sigar_file_system_list_t *fslist)
{
    char name[256];
    char *ptr = name;
    /* XXX: hmm, Find{First,Next}Volume not available in my sdk */
    DWORD len = GetLogicalDriveStringsA(sizeof(name), name);

    DLLMOD_INIT(mpr, TRUE);

    if (len == 0) {
        return GetLastError();
    }

    sigar_file_system_list_create(fslist);

    while (*ptr) {
        sigar_file_system_t *fsp;
        DWORD flags, serialnum=0;
        char fsname[1024];
        UINT drive_type = GetDriveType(ptr);
        int type;

        switch (drive_type) {
          case DRIVE_FIXED:
            type = SIGAR_FSTYPE_LOCAL_DISK;
            break;
          case DRIVE_REMOTE:
            type = SIGAR_FSTYPE_NETWORK;
            break;
          case DRIVE_CDROM:
            type = SIGAR_FSTYPE_CDROM;
            break;
          case DRIVE_RAMDISK:
            type = SIGAR_FSTYPE_RAM_DISK;
            break;
          case DRIVE_REMOVABLE:
            /* skip floppy, usb, etc. drives */
            ptr += strlen(ptr)+1;
            continue;
          default:
            type = SIGAR_FSTYPE_NONE;
            break;
        }

        fsname[0] = '\0';

        GetVolumeInformation(ptr, NULL, 0, &serialnum, NULL,
                             &flags, fsname, sizeof(fsname));

        if (!serialnum && (drive_type == DRIVE_FIXED)) {
            ptr += strlen(ptr)+1;
            continue; /* ignore unformatted partitions */
        }

        SIGAR_FILE_SYSTEM_LIST_GROW(fslist);

        fsp = &fslist->data[fslist->number++];

        fsp->type = type;
        SIGAR_SSTRCPY(fsp->dir_name, ptr);
        SIGAR_SSTRCPY(fsp->dev_name, ptr);

        if ((drive_type == DRIVE_REMOTE) && sigar_WNetGetConnection) {
            DWORD len = sizeof(fsp->dev_name);
            char drive[3] = {'\0', ':', '\0'}; /* e.g. "X:" w/o trailing "\" */
            drive[0] = fsp->dir_name[0];
            sigar_WNetGetConnection(drive, fsp->dev_name, &len);
            /* ignoring failure, leaving dev_name as dir_name */
        }

        /* we set fsp->type, just looking up sigar.c:fstype_names[type] */
        sigar_fs_type_get(fsp);

        if (*fsname == '\0') {
            SIGAR_SSTRCPY(fsp->sys_type_name, fsp->type_name);
        }
        else {
            SIGAR_SSTRCPY(fsp->sys_type_name, fsname); /* CDFS, NTFS, etc */
        }

        get_fs_options(fsp->options, sizeof(fsp->options)-1, flags);

        ptr += strlen(ptr)+1;
    }

    return SIGAR_OK;
}



#define sigar_GetNetworkParams \
    sigar->iphlpapi.get_net_params.func

#define sigar_GetAdaptersInfo \
    sigar->iphlpapi.get_adapters_info.func

#define sigar_GetAdaptersAddresses \
    sigar->iphlpapi.get_adapters_addrs.func

#define sigar_GetNumberOfInterfaces \
    sigar->iphlpapi.get_num_if.func

static sigar_cache_t *sigar_netif_cache_new(sigar_t *sigar)
{
    DWORD num = 0;

    DLLMOD_INIT(iphlpapi, FALSE);

    if (sigar_GetNumberOfInterfaces) {
        DWORD rc = sigar_GetNumberOfInterfaces(&num);

        if (rc == NO_ERROR) {
            sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                             "GetNumberOfInterfaces=%d",
                             num);
        }
        else {
            sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                             "GetNumberOfInterfaces failed: %s",
                             sigar_strerror(sigar, rc));
        }
    }

    if (num == 0) {
        num = 10; /* reasonable default */
    }

    return sigar_cache_new(num);
}

static int sigar_get_adapters_info(sigar_t *sigar,
                                   PIP_ADAPTER_INFO *adapter)
{
    ULONG size = sigar->ifconf_len;
    DWORD rc;

    DLLMOD_INIT(iphlpapi, FALSE);

    if (!sigar_GetAdaptersInfo) {
        return SIGAR_ENOTIMPL;
    }

    *adapter = (PIP_ADAPTER_INFO)sigar->ifconf_buf;
    rc = sigar_GetAdaptersInfo(*adapter, &size);

    if (rc == ERROR_BUFFER_OVERFLOW) {
        sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                         "GetAdaptersInfo "
                         "realloc ifconf_buf old=%d, new=%d",
                         sigar->ifconf_len, size);
        sigar->ifconf_len = size;
        sigar->ifconf_buf = realloc(sigar->ifconf_buf,
                                    sigar->ifconf_len);

        *adapter = (PIP_ADAPTER_INFO)sigar->ifconf_buf;
        rc = sigar_GetAdaptersInfo(*adapter, &size);
    }

    if (rc != NO_ERROR) {
        return rc;
    }
    else {
        return SIGAR_OK;
    }
}


static int sigar_get_adapters_addresses(sigar_t *sigar,
                                        ULONG family, ULONG flags,
                                        PIP_ADAPTER_ADDRESSES *addrs)
{
    ULONG size = sigar->ifconf_len;
    ULONG rc;

    DLLMOD_INIT(iphlpapi, FALSE);

    if (!sigar_GetAdaptersAddresses) {
        return SIGAR_ENOTIMPL;
    }

    *addrs = (PIP_ADAPTER_ADDRESSES)sigar->ifconf_buf;
    rc = sigar_GetAdaptersAddresses(family,
                                    flags,
                                    NULL,
                                    *addrs,
                                    &size);

    if (rc == ERROR_BUFFER_OVERFLOW) {
        sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                         "GetAdaptersAddresses "
                         "realloc ifconf_buf old=%d, new=%d",
                         sigar->ifconf_len, size);
        sigar->ifconf_len = size;
        sigar->ifconf_buf = realloc(sigar->ifconf_buf,
                                    sigar->ifconf_len);

        *addrs = (PIP_ADAPTER_ADDRESSES)sigar->ifconf_buf;
        rc = sigar_GetAdaptersAddresses(family,
                                        flags,
                                        NULL,
                                        *addrs,
                                        &size);
    }

    if (rc != ERROR_SUCCESS) {
        return rc;
    }
    else {
        return SIGAR_OK;
    }
}

#define sigar_GetIpAddrTable \
    sigar->iphlpapi.get_ipaddr_table.func

static int sigar_get_ipaddr_table(sigar_t *sigar,
                                  PMIB_IPADDRTABLE *ipaddr)
{
    ULONG size = sigar->ifconf_len;
    DWORD rc;

    DLLMOD_INIT(iphlpapi, FALSE);

    if (!sigar_GetIpAddrTable) {
        return SIGAR_ENOTIMPL;
    }

    *ipaddr = (PMIB_IPADDRTABLE)sigar->ifconf_buf;
    rc = sigar_GetIpAddrTable(*ipaddr, &size, FALSE);

    if (rc == ERROR_INSUFFICIENT_BUFFER) {
        sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                         "GetIpAddrTable "
                         "realloc ifconf_buf old=%d, new=%d",
                         sigar->ifconf_len, size);
        sigar->ifconf_len = size;
        sigar->ifconf_buf = realloc(sigar->ifconf_buf,
                                    sigar->ifconf_len);

        *ipaddr = (PMIB_IPADDRTABLE)sigar->ifconf_buf;
        rc = sigar_GetIpAddrTable(*ipaddr, &size, FALSE);
    }

    if (rc != NO_ERROR) {
        return rc;
    }
    else {
        return SIGAR_OK;
    }
}

#ifndef MIB_IPADDR_PRIMARY
#define MIB_IPADDR_PRIMARY 0x0001
#endif

static int sigar_get_netif_ipaddr(sigar_t *sigar,
                                  DWORD index,
                                  MIB_IPADDRROW **ipaddr)
{
    sigar_cache_entry_t *entry;
    *ipaddr = NULL;

    if (sigar->netif_addr_rows) {
        entry = sigar_cache_get(sigar->netif_addr_rows, index);
        if (entry->value) {
            *ipaddr = (MIB_IPADDRROW *)entry->value;
        }
    }
    else {
        int status, i;
        MIB_IPADDRTABLE *mib;

        sigar->netif_addr_rows =
            sigar_netif_cache_new(sigar);

        status = sigar_get_ipaddr_table(sigar, &mib);
        if (status != SIGAR_OK) {
            return status;
        }

        for (i=0; i<mib->dwNumEntries; i++) {
            MIB_IPADDRROW *row = &mib->table[i];
            short type;

#ifdef SIGAR_USING_MSC6
            type = row->unused2;
#else
            type = row->wType;
#endif
            if (!(type & MIB_IPADDR_PRIMARY)) {
                continue;
            }

            entry = sigar_cache_get(sigar->netif_addr_rows,
                                    row->dwIndex);
            if (!entry->value) {
                entry->value = malloc(sizeof(*row));
            }
            memcpy(entry->value, row, sizeof(*row));

            if (row->dwIndex == index) {
                *ipaddr = row;
            }
        }
    }

    if (*ipaddr) {
        return SIGAR_OK;
    }
    else {
        return ENOENT;
    }
}

#define sigar_GetIpForwardTable \
    sigar->iphlpapi.get_ipforward_table.func


#define sigar_GetIfTable \
    sigar->iphlpapi.get_if_table.func

#define sigar_GetIfEntry \
    sigar->iphlpapi.get_if_entry.func

static int sigar_get_if_table(sigar_t *sigar, PMIB_IFTABLE *iftable)
{
    ULONG size = sigar->ifconf_len;
    DWORD rc;

    DLLMOD_INIT(iphlpapi, FALSE);

    if (!sigar_GetIfTable) {
        return SIGAR_ENOTIMPL;
    }

    *iftable = (PMIB_IFTABLE)sigar->ifconf_buf;
    rc = sigar_GetIfTable(*iftable, &size, FALSE);

    if (rc == ERROR_INSUFFICIENT_BUFFER) {
        sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                         "GetIfTable "
                         "realloc ifconf_buf old=%d, new=%d",
                         sigar->ifconf_len, size);
        sigar->ifconf_len = size;
        sigar->ifconf_buf = realloc(sigar->ifconf_buf,
                                    sigar->ifconf_len);

        *iftable = (PMIB_IFTABLE)sigar->ifconf_buf;
        rc = sigar_GetIfTable(*iftable, &size, FALSE);
    }

    if (rc != NO_ERROR) {
        return rc;
    }
    else {
        return SIGAR_OK;
    }
}

static int get_mib_ifrow(sigar_t *sigar,
                         const char *name,
                         MIB_IFROW **ifrp)
{
    int status, key, cached=0;
    sigar_cache_entry_t *entry;

    if (sigar->netif_mib_rows) {
        cached = 1;
    }
    else {
        status = sigar_net_interface_list_get(sigar, NULL);
        if (status != SIGAR_OK) {
            return status;
        }
    }
    key = netif_hash(name);
    entry = sigar_cache_get(sigar->netif_mib_rows, key);
    if (!entry->value) {
        return ENOENT;
    }

    *ifrp = (MIB_IFROW *)entry->value;
    if (cached) {
        /* refresh */
        if ((status = sigar_GetIfEntry(*ifrp)) != NO_ERROR) {
            return status;
        }
    }

    return SIGAR_OK;
}

int netif_hash(char *s)
{
    int hash = 0;
    while (*s) {
        hash = 31*hash + *s++;
    }
    return hash;
}

/* Vista and later, wireless network cards are reported as IF_TYPE_IEEE80211 */
#ifndef IF_TYPE_IEEE80211
#define IF_TYPE_IEEE80211 71
#endif

SIGAR_DECLARE(int)
sigar_net_interface_list_get(sigar_t *sigar,
                             sigar_net_interface_list_t *iflist)
{
    MIB_IFTABLE *ift;
    int i, status;
    int lo=0, eth=0, la=0;

    if (!sigar->netif_mib_rows) {
        sigar->netif_mib_rows =
            sigar_netif_cache_new(sigar);
    }

    if (!sigar->netif_names) {
        sigar->netif_names =
            sigar_netif_cache_new(sigar);
    }

    if ((status = sigar_get_if_table(sigar, &ift)) != SIGAR_OK) {
        return status;
    }

    if (iflist) {
        iflist->number = 0;
        iflist->size = ift->dwNumEntries;
        iflist->data =
            malloc(sizeof(*(iflist->data)) * iflist->size);
    }

    for (i=0; i<ift->dwNumEntries; i++) {
        char name[16];
        int key;
        MIB_IFROW *ifr = ift->table + i;
        sigar_cache_entry_t *entry;

        if (strEQ(ifr->bDescr, MS_LOOPBACK_ADAPTER)) {
            /* special-case */
            sprintf(name, NETIF_LA "%d", la++);
        }
        else if (ifr->dwType == MIB_IF_TYPE_LOOPBACK) {
            sprintf(name, "lo%d", lo++);
        }
        else if ((ifr->dwType == MIB_IF_TYPE_ETHERNET) ||
                 (ifr->dwType == IF_TYPE_IEEE80211))
        {
            sprintf(name, "eth%d", eth++);
        }
        else {
            continue; /*XXX*/
        }

        if (iflist) {
            iflist->data[iflist->number++] = sigar_strdup(name);
        }

        key = netif_hash(name);
        entry = sigar_cache_get(sigar->netif_mib_rows, key);
        if (!entry->value) {
            entry->value = malloc(sizeof(*ifr));
        }
        memcpy(entry->value, ifr, sizeof(*ifr));

        /* save dwIndex -> name mapping for use by route_list */
        entry = sigar_cache_get(sigar->netif_names, ifr->dwIndex);
        if (!entry->value) {
            entry->value = sigar_strdup(name);
        }
    }

    return SIGAR_OK;
}

static int sigar_net_interface_ipv6_config_find(sigar_t *sigar, int index,
                                                sigar_net_interface_config_t *ifconfig)
{
#ifdef SIGAR_USING_MSC6
    return SIGAR_ENOTIMPL;
#else
    int status;
    PIP_ADAPTER_ADDRESSES aa, addrs;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

    status = sigar_get_adapters_addresses(sigar, AF_UNSPEC, flags, &aa);

    if (status != SIGAR_OK) {
        return status;
    }

    for (addrs = aa; addrs; addrs = addrs->Next) {
        PIP_ADAPTER_UNICAST_ADDRESS addr;
        if (addrs->IfIndex != index) {
            continue;
        }
        for (addr = addrs->FirstUnicastAddress; addr; addr = addr->Next) {
            struct sockaddr *sa = addr->Address.lpSockaddr;

            if (sa->sa_family == AF_INET6) {
                struct in6_addr *inet6 = SIGAR_SIN6_ADDR(sa);

                sigar_net_address6_set(ifconfig->address6, inet6);
                sigar_net_interface_scope6_set(ifconfig, inet6);
                if (addrs->FirstPrefix) {
                    ifconfig->prefix6_length = addrs->FirstPrefix->PrefixLength;
                }
                return SIGAR_OK;
            }
        }
    }
    return SIGAR_ENOENT;
#endif
}

SIGAR_DECLARE(int)
sigar_net_interface_config_get(sigar_t *sigar,
                               const char *name,
                               sigar_net_interface_config_t *ifconfig)
{
    MIB_IFROW *ifr;
    MIB_IPADDRROW *ipaddr;
    int status;

    if (!name) {
        return sigar_net_interface_config_primary_get(sigar, ifconfig);
    }

    status = get_mib_ifrow(sigar, name, &ifr);
    if (status != SIGAR_OK) {
        return status;
    }

    SIGAR_ZERO(ifconfig);

    SIGAR_SSTRCPY(ifconfig->name, name);

    ifconfig->mtu = ifr->dwMtu;

    sigar_net_address_mac_set(ifconfig->hwaddr,
                              ifr->bPhysAddr,
                              SIGAR_IFHWADDRLEN);

    SIGAR_SSTRCPY(ifconfig->description,
                  ifr->bDescr);

    if (ifr->dwOperStatus & MIB_IF_OPER_STATUS_OPERATIONAL) {
        ifconfig->flags |= SIGAR_IFF_UP|SIGAR_IFF_RUNNING;
    }

    status = sigar_get_netif_ipaddr(sigar,
                                    ifr->dwIndex,
                                    &ipaddr);

    if (status == SIGAR_OK) {
        sigar_net_address_set(ifconfig->address,
                              ipaddr->dwAddr);

        sigar_net_address_set(ifconfig->netmask,
                              ipaddr->dwMask);

        if (ifr->dwType != MIB_IF_TYPE_LOOPBACK) {
            if (ipaddr->dwBCastAddr) {
                long bcast =
                    ipaddr->dwAddr & ipaddr->dwMask;

                bcast |= ~ipaddr->dwMask;
                ifconfig->flags |= SIGAR_IFF_BROADCAST;

                sigar_net_address_set(ifconfig->broadcast,
                                      bcast);
            }
        }
    }

    /* hack for MS_LOOPBACK_ADAPTER */
    if (strnEQ(name, NETIF_LA, sizeof(NETIF_LA)-1)) {
        ifr->dwType = MIB_IF_TYPE_LOOPBACK;
    }

    if (ifr->dwType == MIB_IF_TYPE_LOOPBACK) {
        ifconfig->flags |= SIGAR_IFF_LOOPBACK;

        SIGAR_SSTRCPY(ifconfig->type,
                      SIGAR_NIC_LOOPBACK);
    }
    else {
        if (ipaddr) {
            ifconfig->flags |= SIGAR_IFF_MULTICAST;
        }

        SIGAR_SSTRCPY(ifconfig->type,
                      SIGAR_NIC_ETHERNET);
    }

    sigar_net_interface_ipv6_config_init(ifconfig);
    sigar_net_interface_ipv6_config_find(sigar, ifr->dwIndex, ifconfig);

    return SIGAR_OK;
}

#define IS_TCP_SERVER(state, flags) \
    ((flags & SIGAR_NETCONN_SERVER) && (state == MIB_TCP_STATE_LISTEN))

#define IS_TCP_CLIENT(state, flags) \
    ((flags & SIGAR_NETCONN_CLIENT) && (state != MIB_TCP_STATE_LISTEN))

#define sigar_GetTcpTable \
    sigar->iphlpapi.get_tcp_table.func

static int net_conn_get_tcp(sigar_net_connection_walker_t *walker)
{
    sigar_t *sigar = walker->sigar;
    int flags = walker->flags;
    int i;
    DWORD rc, size=0;
    PMIB_TCPTABLE tcp;

    DLLMOD_INIT(iphlpapi, FALSE);

    if (!sigar_GetTcpTable) {
        return SIGAR_ENOTIMPL;
    }

    rc = sigar_GetTcpTable(NULL, &size, FALSE);
    if (rc != ERROR_INSUFFICIENT_BUFFER) {
        return GetLastError();
    }
    tcp = malloc(size);
    rc = sigar_GetTcpTable(tcp, &size, FALSE);
    if (rc) {
        free(tcp);
        return GetLastError();
    }

    /* go in reverse to get LISTEN states first */
    for (i = (tcp->dwNumEntries-1); i >= 0; i--) {
        sigar_net_connection_t conn;
        DWORD state = tcp->table[i].dwState;

        if (!(IS_TCP_SERVER(state, flags) ||
              IS_TCP_CLIENT(state, flags)))
        {
            continue;
        }

        conn.local_port  = htons((WORD)tcp->table[i].dwLocalPort);
        conn.remote_port = htons((WORD)tcp->table[i].dwRemotePort);

        conn.type = SIGAR_NETCONN_TCP;

        sigar_net_address_set(conn.local_address,
                              tcp->table[i].dwLocalAddr);

        sigar_net_address_set(conn.remote_address,
                              tcp->table[i].dwRemoteAddr);

        conn.send_queue = conn.receive_queue = SIGAR_FIELD_NOTIMPL;

        switch (state) {
          case MIB_TCP_STATE_CLOSED:
            conn.state = SIGAR_TCP_CLOSE;
            break;
          case MIB_TCP_STATE_LISTEN:
            conn.state = SIGAR_TCP_LISTEN;
            break;
          case MIB_TCP_STATE_SYN_SENT:
            conn.state = SIGAR_TCP_SYN_SENT;
            break;
          case MIB_TCP_STATE_SYN_RCVD:
            conn.state = SIGAR_TCP_SYN_RECV;
            break;
          case MIB_TCP_STATE_ESTAB:
            conn.state = SIGAR_TCP_ESTABLISHED;
            break;
          case MIB_TCP_STATE_FIN_WAIT1:
            conn.state = SIGAR_TCP_FIN_WAIT1;
            break;
          case MIB_TCP_STATE_FIN_WAIT2:
            conn.state = SIGAR_TCP_FIN_WAIT2;
            break;
          case MIB_TCP_STATE_CLOSE_WAIT:
            conn.state = SIGAR_TCP_CLOSE_WAIT;
            break;
          case MIB_TCP_STATE_CLOSING:
            conn.state = SIGAR_TCP_CLOSING;
            break;
          case MIB_TCP_STATE_LAST_ACK:
            conn.state = SIGAR_TCP_LAST_ACK;
            break;
          case MIB_TCP_STATE_TIME_WAIT:
            conn.state = SIGAR_TCP_TIME_WAIT;
            break;
          case MIB_TCP_STATE_DELETE_TCB:
          default:
            conn.state = SIGAR_TCP_UNKNOWN;
            break;
        }

        if (walker->add_connection(walker, &conn) != SIGAR_OK) {
            break;
        }
    }

    free(tcp);
    return SIGAR_OK;
}

static int net_conn_get_udp(sigar_net_connection_walker_t *walker)
{
    /* Disabled because it isn't properly implemented and
     * cause the windows runtime to abort due to use
     * of uninitialized variable in the for-loop below.
     * IS_UDP_SERVER(conn, flags) We don't use this
     * functionality anyway
     */
    return SIGAR_ENOTIMPL;
}

SIGAR_DECLARE(int)
sigar_net_connection_walk(sigar_net_connection_walker_t *walker)
{
    int status;

    if (walker->flags & SIGAR_NETCONN_TCP) {
        status = net_conn_get_tcp(walker);

        if (status != SIGAR_OK) {
            return status;
        }
    }

    if (walker->flags & SIGAR_NETCONN_UDP) {
        status = net_conn_get_udp(walker);

        if (status != SIGAR_OK) {
            return status;
        }
    }

    return SIGAR_OK;
}
