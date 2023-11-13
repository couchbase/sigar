/*
 * Copyright (c) 2007-2008 Hyperic, Inc.
 * Copyright (c) 2009 SpringSource, Inc.
 * Copyright (c) 2010 VMware, Inc.
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

/* Utility functions to provide string formatting of SIGAR data */

// If it wasn't for the stupid CentOS7 we could undefine _GNU_SOURCE
// and get the portable version of strerror_r
#include "sigar.h"
#include "sigar_private.h"
#include <sigar/sigar.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#ifdef WIN32
#include <windows.h>
#endif

static const char* sigar_error_string(int err) {
    switch (err) {
    case SIGAR_ENOTIMPL:
        return "This function has not been implemented on this platform";
    case SIGAR_NO_SUCH_PROCESS:
        return "No such process";
    default:
        return "Error string not specified yet";
    }
}

static const char* sigar_strerror_get(int err, char* errbuf, int buflen) {
#ifdef WIN32
    /* force english error message */
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  nullptr,
                  err,
                  MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                  (LPTSTR)errbuf,
                  (DWORD)buflen,
                  nullptr);
#elif defined(_GNU_SOURCE)
    if (!strerror_r(err, errbuf, buflen)) {
        SIGAR_STRNCPY(errbuf, "Unknown error", buflen);
    }
#else
    int ret = strerror_r(err, errbuf, buflen);
    if (ret != EINVAL) {
        SIGAR_STRNCPY(errbuf, "Unknown error", buflen);
    }
#endif
    return errbuf;
}

SIGAR_DECLARE(const char*) sigar_strerror(sigar_t* sigar, int err) {
    if (err < 0) {
        return sigar->errbuf.data();
    }

    if (err > SIGAR_START_ERROR) {
        return sigar_error_string(err);
    }

    return sigar_strerror_get(err, sigar->errbuf.data(), sigar->errbuf.size());
}
