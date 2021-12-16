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

#pragma once

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


#define SIGAR_NO_SUCH_PROCESS (SIGAR_OS_START_ERROR+1)
