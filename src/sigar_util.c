/*
 * Copyright (c) 2004-2009 Hyperic, Inc.
 * Copyright (c) 2009 SpringSource, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#include "sigar.h"
#include "sigar_private.h"
#include "sigar_util.h"
#include "sigar_os.h"

#ifndef WIN32

#include <dirent.h>
#include <sys/stat.h>

char *sigar_uitoa(char *buf, unsigned int n, int *len)
{
    char *start = buf + UITOA_BUFFER_SIZE - 1;

    *start = 0;

    do {
        *--start = '0' + (n % 10);
        ++*len;
        n /= 10;
    } while (n);

    return start;
}

char *sigar_skip_token(char *p)
{
    while (sigar_isspace(*p)) p++;
    while (*p && !sigar_isspace(*p)) p++;
    return p;
}

/* avoiding sprintf */

char *sigar_proc_filename(char *buffer, int buflen,
                          sigar_pid_t bigpid,
                          const char *fname, int fname_len)
{
    int len = 0;
    char *ptr = buffer;
    unsigned int pid = (unsigned int)bigpid; /* XXX -- This isn't correct */
    char pid_buf[UITOA_BUFFER_SIZE];
    char *pid_str = sigar_uitoa(pid_buf, pid, &len);

    assert((unsigned int)buflen >=
           (SSTRLEN(PROCP_FS_ROOT) + UITOA_BUFFER_SIZE + fname_len + 1));

    memcpy(ptr, PROCP_FS_ROOT, SSTRLEN(PROCP_FS_ROOT));
    ptr += SSTRLEN(PROCP_FS_ROOT);

    memcpy(ptr, pid_str, len);
    ptr += len;

    memcpy(ptr, fname, fname_len);
    ptr += fname_len;
    *ptr = '\0';

    return buffer;
}

int sigar_proc_file2str(char *buffer, int buflen,
                        sigar_pid_t pid,
                        const char *fname,
                        int fname_len)
{
    int retval;

    buffer = sigar_proc_filename(buffer, buflen, pid,
                                 fname, fname_len);

    retval = sigar_file2str(buffer, buffer, buflen);

    if (retval != SIGAR_OK) {
        switch (retval) {
          case ENOENT:
            retval = ESRCH; /* no such process */
          default:
            break;
        }
    }

    return retval;
}

#endif /* WIN32 */

int sigar_mem_calc_ram(sigar_t *sigar, sigar_mem_t *mem)
{
    sigar_int64_t total = mem->total / 1024, diff;
    sigar_uint64_t lram = (mem->total / (1024 * 1024));
    int ram = (int)lram; /* must cast after division */
    int remainder = ram % 8;

    if (remainder > 0) {
        ram += (8 - remainder);
    }

    mem->ram = ram;

    diff = total - (mem->actual_free / 1024);
    mem->used_percent =
        (double)(diff * 100) / total;

    diff = total - (mem->actual_used / 1024);
    mem->free_percent =
        (double)(diff * 100) / total;

    return ram;
}

/* common to win32 and linux */

int sigar_file2str(const char *fname, char *buffer, int buflen)
{
    int len, status;
    int fd = open(fname, O_RDONLY);

    if (fd < 0) {
        return ENOENT;
    }

    if ((len = read(fd, buffer, buflen)) < 0) {
        status = errno;
    }
    else {
        status = SIGAR_OK;
        buffer[len] = '\0';
    }
    close(fd);

    return status;
}

#ifdef WIN32
#define vsnprintf _vsnprintf
#endif

#ifdef WIN32
#   define rindex strrchr
#endif

SIGAR_DECLARE(void) sigar_log_printf(sigar_t *sigar, int level,
                                     const char *format, ...)
{
    va_list args;
    char buffer[8192];

    if (level > sigar->log_level) {
        return;
    }

    if (!sigar->log_impl) {
        return;
    }

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    sigar->log_impl(sigar, sigar->log_data, level, buffer);
}

SIGAR_DECLARE(void) sigar_log(sigar_t *sigar, int level, char *message)
{
    if (level > sigar->log_level) {
        return;
    }

    if (!sigar->log_impl) {
        return;
    }

    sigar->log_impl(sigar, sigar->log_data, level, message);
}

SIGAR_DECLARE(void) sigar_log_impl_set(sigar_t *sigar, void *data,
                                       sigar_log_impl_t impl)
{
    sigar->log_data = data;
    sigar->log_impl = impl;
}

SIGAR_DECLARE(int) sigar_log_level_get(sigar_t *sigar)
{
    return sigar->log_level;
}

static const char *log_levels[] = {
    "FATAL",
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG",
    "TRACE"
};

SIGAR_DECLARE(const char *) sigar_log_level_string_get(sigar_t *sigar)
{
    return log_levels[sigar->log_level];
}

SIGAR_DECLARE(void) sigar_log_level_set(sigar_t *sigar, int level)
{
    sigar->log_level = level;
}

SIGAR_DECLARE(void) sigar_log_impl_file(sigar_t *sigar, void *data,
                                        int level, char *message)
{
    FILE *fp = (FILE*)data;
    fprintf(fp, "[%s] %s\n", log_levels[level], message);
}

#ifndef WIN32
#include <sys/time.h>
sigar_int64_t sigar_time_now_millis(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((tv.tv_sec * SIGAR_USEC) + tv.tv_usec) / SIGAR_MSEC;
}
#endif
