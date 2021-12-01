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

#ifndef SIGAR_OS_H
#define SIGAR_OS_H

#ifndef __GNUC__
#if _MSC_VER <= 1200
#define SIGAR_USING_MSC6 /* Visual Studio version 6 */
#endif
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <winreg.h>
#include <winperf.h>
#include <ws2tcpip.h>
#include <stddef.h>
#include <sys/types.h>
#include <malloc.h>
#include <stdio.h>
#include <errno.h>
#include <tlhelp32.h>
#include <stdint.h>

#include <iptypes.h>

#include "sigar_util.h"

#ifndef __GNUC__
/* see apr/include/arch/win32/atime.h */
#define EPOCH_DELTA INT64_C(11644473600000000)
#else
#define EPOCH_DELTA 11644473600000000LL
#endif

#define SIGAR_CMDLINE_MAX 4096

/* XXX: support CP_UTF8 ? */

#define SIGAR_A2W(lpa, lpw, bytes) \
    (lpw[0] = 0, MultiByteToWideChar(CP_ACP, 0, \
                                     lpa, -1, lpw, (bytes/sizeof(WCHAR))))

#define SIGAR_W2A(lpw, lpa, chars) \
    (lpa[0] = '\0', WideCharToMultiByte(CP_ACP, 0, \
                                        lpw, -1, (LPSTR)lpa, chars, \
                                        NULL, NULL))

/* iptypes.h from vc7, not available in vc6 */
/* copy from PSDK if using vc6 */
#include "iptypes.h"

#ifdef SIGAR_USING_MSC6

/* from winbase.h not in vs6.0 */
typedef struct {
    DWORD dwLength;
    DWORD dwMemoryLoad;
    DWORDLONG ullTotalPhys;
    DWORDLONG ullAvailPhys;
    DWORDLONG ullTotalPageFile;
    DWORDLONG ullAvailPageFile;
    DWORDLONG ullTotalVirtual;
    DWORDLONG ullAvailVirtual;
    DWORDLONG ullAvailExtendedVirtual;
} MEMORYSTATUSEX;

/* service manager stuff not in vs6.0 */
typedef struct _SERVICE_STATUS_PROCESS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
    DWORD dwProcessId;
    DWORD dwServiceFlags;
} SERVICE_STATUS_PROCESS;

typedef enum {
    SC_STATUS_PROCESS_INFO = 0
} SC_STATUS_TYPE;

#ifndef ERROR_DATATYPE_MISMATCH
#define ERROR_DATATYPE_MISMATCH 1629L
#endif

#endif /* _MSC_VER */

#include <iprtrmib.h>

/* undocumented structures */
typedef struct {
    DWORD   dwState;
    DWORD   dwLocalAddr;
    DWORD   dwLocalPort;
    DWORD   dwRemoteAddr;
    DWORD   dwRemotePort;
    DWORD   dwProcessId;
} MIB_TCPEXROW, *PMIB_TCPEXROW;

typedef struct {
    DWORD dwNumEntries;
    MIB_TCPEXROW table[ANY_SIZE];
} MIB_TCPEXTABLE, *PMIB_TCPEXTABLE;

typedef struct {
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwProcessId;
} MIB_UDPEXROW, *PMIB_UDPEXROW;

typedef struct {
    DWORD dwNumEntries;
    MIB_UDPEXROW table[ANY_SIZE];
} MIB_UDPEXTABLE, *PMIB_UDPEXTABLE;

/* end undocumented structures */

/* no longer in the standard header files */
typedef struct {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

#define SystemProcessorPerformanceInformation 8

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

typedef struct {
    const char *name;
    HINSTANCE handle;
} sigar_dll_handle_t;

typedef struct {
    const char *name;
    FARPROC func;
} sigar_dll_func_t;

typedef struct {
    const char *name;
    HINSTANCE handle;
    sigar_dll_func_t funcs[12];
} sigar_dll_module_t;

/* advapi32.dll */
typedef BOOL (CALLBACK *advapi_convert_string_sid)(LPCSTR,
                                                   PSID *);

typedef BOOL (CALLBACK *advapi_query_service_status)(SC_HANDLE,
                                                     SC_STATUS_TYPE,
                                                     LPBYTE,
                                                     DWORD,
                                                     LPDWORD);

/* ntdll.dll */
typedef DWORD (CALLBACK *ntdll_query_sys_info)(DWORD,
                                               PVOID,
                                               ULONG,
                                               PULONG);

typedef DWORD (CALLBACK *ntdll_query_proc_info)(HANDLE,
                                                DWORD,
                                                PVOID,
                                                ULONG,
                                                PULONG);

/* psapi.dll */
typedef BOOL (CALLBACK *psapi_enum_modules)(HANDLE,
                                            HMODULE *,
                                            DWORD,
                                            LPDWORD);

typedef DWORD (CALLBACK *psapi_get_module_name)(HANDLE,
                                                HMODULE,
                                                LPTSTR,
                                                DWORD);

typedef BOOL (CALLBACK *psapi_enum_processes)(DWORD *,
                                              DWORD,
                                              DWORD *);

/* kernel32.dll */
typedef BOOL (CALLBACK *kernel_memory_status)(MEMORYSTATUSEX *);


#define SIGAR_DLLFUNC(api, name) \
    struct { \
         const char *name; \
         api##_##name func; \
    } name

typedef struct {
    sigar_dll_handle_t handle;

    SIGAR_DLLFUNC(advapi, convert_string_sid);
    SIGAR_DLLFUNC(advapi, query_service_status);

    sigar_dll_func_t end;
} sigar_advapi_t;

typedef struct {
    sigar_dll_handle_t handle;

    SIGAR_DLLFUNC(ntdll, query_sys_info);
    SIGAR_DLLFUNC(ntdll, query_proc_info);

    sigar_dll_func_t end;
} sigar_ntdll_t;

typedef struct {
    sigar_dll_handle_t handle;

    SIGAR_DLLFUNC(psapi, enum_modules);
    SIGAR_DLLFUNC(psapi, enum_processes);
    SIGAR_DLLFUNC(psapi, get_module_name);

    sigar_dll_func_t end;
} sigar_psapi_t;

typedef struct {
    sigar_dll_handle_t handle;

    SIGAR_DLLFUNC(kernel, memory_status);

    sigar_dll_func_t end;
} sigar_kernel_t;

struct sigar_t {
    SIGAR_T_BASE;
    char *machine;
    int using_wide;
    long pagesize;
    HKEY handle;
    char *perfbuf;
    DWORD perfbuf_size;
    sigar_advapi_t advapi;
    sigar_ntdll_t ntdll;
    sigar_psapi_t psapi;
    sigar_kernel_t kernel;
    sigar_win32_pinfo_t pinfo;

    int ht_enabled;
    int lcpu; //number of logical cpus
    int winnt;
};

#ifdef __cplusplus
extern "C" {
#endif

uint64_t sigar_FileTimeToTime(FILETIME *ft);

int sigar_proc_args_peb_get(sigar_t *sigar, HANDLE proc,
                            sigar_proc_args_t *procargs);

int sigar_proc_env_peb_get(sigar_t *sigar, HANDLE proc,
                           WCHAR *env, DWORD envlen);

int sigar_parse_proc_args(sigar_t *sigar, WCHAR *buf,
                          sigar_proc_args_t *procargs);


int sigar_os_check_parents(sigar_t* sigar, sigar_pid_t pid, sigar_pid_t ppid);
int get_proc_info(sigar_t* sigar, sigar_pid_t pid);

typedef struct {
    WORD product_major;
    WORD product_minor;
    WORD product_build;
    WORD product_revision;
    WORD file_major;
    WORD file_minor;
    WORD file_build;
    WORD file_revision;
} sigar_file_version_t;

#ifdef __cplusplus
}
#endif

#define SIGAR_NO_SUCH_PROCESS (SIGAR_OS_START_ERROR+1)

#endif /* SIGAR_OS_H */
