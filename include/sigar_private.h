/*
 * Copyright (c) 2004-2008 Hyperic, Inc.
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

#ifndef SIGAR_PRIVATE_DOT_H
#define SIGAR_PRIVATE_DOT_H

#include "sigar_log.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef WIN32
#include <unistd.h>
#include <stddef.h>
#ifndef DARWIN
#include <strings.h>
#endif
#endif

#ifdef DMALLOC
#define _MEMORY_H /* exclude memory.h on solaris */
#define DMALLOC_FUNC_CHECK
#include <dmalloc.h>
#endif

/* common to all os sigar_t's */
/* XXX: this is ugly; but don't want the same stuffs
 * duplicated on 4 platforms and am too lazy to change
 * sigar_t to the way it was originally where sigar_t was
 * common and contained a sigar_os_t.
 * feel free trav ;-)
 */
#define SIGAR_T_BASE \
   int log_level; \
   void *log_data; \
   sigar_log_impl_t log_impl; \
   unsigned long version; \
   unsigned long boot_time; \
   int ticks; \
   sigar_pid_t pid; \
   char errbuf[256]; \
   char *self_path; \
   sigar_proc_list_t *pids; \
   sigar_cache_t *proc_cpu

#ifdef DMALLOC
/* linux has its own strdup macro, make sure we use dmalloc's */
#define sigar_strdup(s) \
    dmalloc_strndup(__FILE__, __LINE__, (s), -1, 0)
#else
#  ifdef WIN32
#    define sigar_strdup(s) _strdup(s)
#  else
#    define sigar_strdup(s) strdup(s)
#  endif
#endif

#define SIGAR_ZERO(s) \
    memset(s, '\0', sizeof(*(s)))

#define SIGAR_STRNCPY(dest, src, len) \
    strncpy(dest, src, len); \
    dest[len-1] = '\0'

/* we use fixed size buffers pretty much everywhere */
/* this is strncpy + ensured \0 terminator */
#define SIGAR_SSTRCPY(dest, src) \
    SIGAR_STRNCPY(dest, src, sizeof(dest))

#ifndef strEQ
#define strEQ(s1, s2) (strcmp(s1, s2) == 0)
#endif

#ifndef strnEQ
#define strnEQ(s1, s2, n) (strncmp(s1, s2, n) == 0)
#endif

#ifdef WIN32
#define strcasecmp stricmp
#define strncasecmp strnicmp
#endif

#ifndef strcaseEQ
#define strcaseEQ(s1, s2) (strcasecmp(s1, s2) == 0)
#endif

#ifndef strncaseEQ
#define strncaseEQ(s1, s2, n) (strncasecmp(s1, s2, n) == 0)
#endif

#ifdef offsetof
#define sigar_offsetof offsetof
#else
#define sigar_offsetof(type, field) ((size_t)(&((type *)0)->field))
#endif

#define SIGAR_MSEC 1000L
#define SIGAR_USEC 1000000L
#define SIGAR_NSEC 1000000000L

#define SIGAR_SEC2NANO(s) \
    ((sigar_uint64_t)(s) * (sigar_uint64_t)SIGAR_NSEC)

/* cpu ticks to milliseconds */
#define SIGAR_TICK2MSEC(s) \
   ((sigar_uint64_t)(s) * ((sigar_uint64_t)SIGAR_MSEC / (double)sigar->ticks))

#define SIGAR_TICK2NSEC(s) \
   ((sigar_uint64_t)(s) * ((sigar_uint64_t)SIGAR_NSEC / (double)sigar->ticks))

/* nanoseconds to milliseconds */
#define SIGAR_NSEC2MSEC(s) \
   ((sigar_uint64_t)(s) / ((sigar_uint64_t)1000000L))

#define SIGAR_LAST_PROC_EXPIRE 2

#define SIGAR_CPU_INFO_MAX 4

#define SIGAR_CPU_LIST_MAX 4

#define SIGAR_PROC_LIST_MAX 256

#define SIGAR_PROC_ARGS_MAX 12

int sigar_os_open(sigar_t **sigar);

int sigar_os_close(sigar_t *sigar);

char *sigar_os_error_string(sigar_t *sigar, int err);

char *sigar_strerror_get(int err, char *errbuf, int buflen);

void sigar_strerror_set(sigar_t *sigar, char *msg);

void sigar_strerror_printf(sigar_t *sigar, const char *format, ...);

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist);

int sigar_os_proc_list_get_children(sigar_t* sigar,
                                    sigar_pid_t ppid,
                                    sigar_proc_list_t* proclist);

int sigar_proc_list_create(sigar_proc_list_t *proclist);

int sigar_proc_list_grow(sigar_proc_list_t *proclist);

#define SIGAR_PROC_LIST_GROW(proclist) \
    if (proclist->number >= proclist->size) { \
        sigar_proc_list_grow(proclist); \
    }

int sigar_proc_args_create(sigar_proc_args_t *proclist);

int sigar_proc_args_grow(sigar_proc_args_t *procargs);

#define SIGAR_PROC_ARGS_GROW(procargs) \
    if (procargs->number >= procargs->size) { \
        sigar_proc_args_grow(procargs); \
    }

#ifndef WIN32
#include <netdb.h>
#endif

#endif
