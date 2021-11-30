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

#include "sigar.h"
#include "sigar_private.h"
#include "sigar_util.h"
#include "sigar_os.h"

#include <stdio.h>

static char *sigar_error_string(int err)
{
    switch (err) {
      case SIGAR_ENOTIMPL:
        return "This function has not been implemented on this platform";
      default:
        return "Error string not specified yet";
    }
}

SIGAR_DECLARE(char *) sigar_strerror(sigar_t *sigar, int err)
{
    char *buf;

    if (err < 0) {
        return sigar->errbuf;
    }

    if (err > SIGAR_OS_START_ERROR) {
        if ((buf = sigar_os_error_string(sigar, err)) != NULL) {
            return buf;
        }
        return "Unknown OS Error"; /* should never happen */
    }

    if (err > SIGAR_START_ERROR) {
        return sigar_error_string(err);
    }

    return sigar_strerror_get(err, sigar->errbuf, sizeof(sigar->errbuf));
}

char *sigar_strerror_get(int err, char *errbuf, int buflen)
{
    char *buf = NULL;
#ifdef WIN32
    DWORD len;

    len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL,
                        err,
                        MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), /* force english */
                        (LPTSTR)errbuf,
                        (DWORD)buflen,
                        NULL);
#else

#if defined(HAVE_STRERROR_R) && defined(HAVE_STRERROR_R_GLIBC)
    /*
     * strerror_r man page says:
     * "The GNU version may, but need not, use the user supplied buffer"
     */
    buf = strerror_r(err, errbuf, buflen);
#elif defined(HAVE_STRERROR_R)
    if (strerror_r(err, errbuf, buflen) < 0) {
        buf = "Unknown Error";
    }
#else
    /* strerror() is thread safe on solaris and hpux */
    buf = strerror(err);
#endif

    if (buf != NULL) {
        SIGAR_STRNCPY(errbuf, buf, buflen);
    }

#endif
    return errbuf;
}

