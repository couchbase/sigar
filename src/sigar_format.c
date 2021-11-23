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
#include "sigar_format.h"

#include <errno.h>
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

void sigar_strerror_set(sigar_t *sigar, char *msg)
{
    SIGAR_SSTRCPY(sigar->errbuf, msg);
}

#ifdef WIN32
#define vsnprintf _vsnprintf
#endif

void sigar_strerror_printf(sigar_t *sigar, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    vsnprintf(sigar->errbuf, sizeof(sigar->errbuf), format, args);
    va_end(args);
}

/* copy apr_strfsize */
SIGAR_DECLARE(char *) sigar_format_size(sigar_uint64_t size, char *buf)
{
    const char ord[] = "KMGTPE";
    const char *o = ord;
    int remain;

    if (size == SIGAR_FIELD_NOTIMPL) {
        buf[0] = '-';
        buf[1] = '\0';
        return buf;
    }

    if (size < 973) {
        sprintf(buf, "%3d ", (int) size);
        return buf;
    }

    do {
        remain = (int)(size & 1023);
        size >>= 10;

        if (size >= 973) {
            ++o;
            continue;
        }

        if (size < 9 || (size == 9 && remain < 973)) {
            if ((remain = ((remain * 5) + 256) / 512) >= 10) {
                ++size;
                remain = 0;
            }
            sprintf(buf, "%d.%d%c", (int) size, remain, *o);
            return buf;
        }

        if (remain >= 512) {
            ++size;
        }

        sprintf(buf, "%3d%c", (int) size, *o);

        return buf;
    } while (1);
}


SIGAR_DECLARE(int) sigar_uptime_string(sigar_t *sigar,
                                       sigar_uptime_t *uptime,
                                       char *buffer,
                                       int buflen)
{
    char *ptr = buffer;
    int time = (int)uptime->uptime;
    int minutes, hours, days, offset = 0;

    /* XXX: get rid of sprintf and/or check for overflow */
    days = time / (60*60*24);

    if (days) {
        offset += sprintf(ptr + offset, "%d day%s, ",
                          days, (days > 1) ? "s" : "");
    }

    minutes = time / 60;
    hours = minutes / 60;
    hours = hours % 24;
    minutes = minutes % 60;

    if (hours) {
        offset += sprintf(ptr + offset, "%2d:%02d",
                          hours, minutes);
    }
    else {
        offset += sprintf(ptr + offset, "%d min", minutes);
    }

    return SIGAR_OK;
}

SIGAR_DECLARE(int) sigar_cpu_perc_calculate(sigar_cpu_t *prev,
                                            sigar_cpu_t *curr,
                                            sigar_cpu_perc_t *perc)
{
    double diff_user, diff_sys, diff_nice, diff_idle;
    double diff_wait, diff_irq, diff_soft_irq, diff_stolen;
    double diff_total;

    diff_user = curr->user - prev->user;
    diff_sys  = curr->sys  - prev->sys;
    diff_nice = curr->nice - prev->nice;
    diff_idle = curr->idle - prev->idle;
    diff_wait = curr->wait - prev->wait;
    diff_irq = curr->irq - prev->irq;
    diff_soft_irq = curr->soft_irq - prev->soft_irq;
    diff_stolen = curr->stolen - prev->stolen;

    diff_user = diff_user < 0 ? 0 : diff_user;
    diff_sys  = diff_sys  < 0 ? 0 : diff_sys;
    diff_nice = diff_nice < 0 ? 0 : diff_nice;
    diff_idle = diff_idle < 0 ? 0 : diff_idle;
    diff_wait = diff_wait < 0 ? 0 : diff_wait;
    diff_irq = diff_irq < 0 ? 0 : diff_irq;
    diff_soft_irq = diff_soft_irq < 0 ? 0 : diff_soft_irq;
    diff_stolen = diff_stolen < 0 ? 0 : diff_stolen;

    diff_total =
        diff_user + diff_sys + diff_nice + diff_idle +
        diff_wait + diff_irq + diff_soft_irq +
        diff_stolen;

    perc->user = diff_user / diff_total;
    perc->sys  = diff_sys / diff_total;
    perc->nice = diff_nice / diff_total;
    perc->idle = diff_idle / diff_total;
    perc->wait = diff_wait / diff_total;
    perc->irq = diff_irq / diff_total;
    perc->soft_irq = diff_soft_irq / diff_total;
    perc->stolen = diff_stolen / diff_total;

    perc->combined =
        perc->user + perc->sys + perc->nice + perc->wait;

    return SIGAR_OK;
}
