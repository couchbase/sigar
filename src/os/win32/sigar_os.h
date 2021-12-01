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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winreg.h>
#include <winperf.h>
#include <stddef.h>
#include <sys/types.h>
#include <malloc.h>
#include <stdio.h>
#include <errno.h>
#include <tlhelp32.h>
#include <stdint.h>

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

#define SIGAR_DLLFUNC(api, name) \
    struct { \
         const char *name; \
         api##_##name func; \
    } name

typedef struct {
    sigar_dll_handle_t handle;

    SIGAR_DLLFUNC(psapi, enum_modules);
    SIGAR_DLLFUNC(psapi, enum_processes);
    SIGAR_DLLFUNC(psapi, get_module_name);

    sigar_dll_func_t end;
} sigar_psapi_t;

struct sigar_t {
    SIGAR_T_BASE;
    char *machine;
    int using_wide;
    long pagesize;
    HKEY handle;
    char *perfbuf;
    DWORD perfbuf_size;
    sigar_psapi_t psapi;
    sigar_win32_pinfo_t pinfo;
};

#ifdef __cplusplus
extern "C" {
#endif

int sigar_os_check_parents(sigar_t* sigar, sigar_pid_t pid, sigar_pid_t ppid);
int get_proc_info(sigar_t* sigar, sigar_pid_t pid);

#ifdef __cplusplus
}
#endif

#define SIGAR_NO_SUCH_PROCESS (SIGAR_OS_START_ERROR+1)

#endif /* SIGAR_OS_H */
