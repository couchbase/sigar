/*
 * Copyright (c) 2004-2008 Hyperic, Inc.
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

#ifndef SIGAR_UTIL_H
#define SIGAR_UTIL_H

/* most of this is crap for dealing with linux /proc */
#define UITOA_BUFFER_SIZE \
    (sizeof(int) * 3 + 1)

#define SSTRLEN(s) \
    (sizeof(s)-1)

#define sigar_strtoul(ptr) \
    strtoul(ptr, &ptr, 10)

#define sigar_strtoull(ptr) \
    strtoull(ptr, &ptr, 10)

#define sigar_isspace(c) \
    (isspace(((unsigned char)(c))))

#define sigar_isdigit(c) \
    (isdigit(((unsigned char)(c))))

#define sigar_isalpha(c) \
    (isalpha(((unsigned char)(c))))

#define sigar_isupper(c) \
    (isupper(((unsigned char)(c))))

#define sigar_tolower(c) \
    (tolower(((unsigned char)(c))))

#ifdef WIN32
#define sigar_fileno _fileno
#define sigar_isatty _isatty
#define sigar_write  _write
#else
#define sigar_fileno fileno
#define sigar_isatty isatty
#define sigar_write  write
#endif

#ifndef PROC_FS_ROOT
#define PROC_FS_ROOT "/proc/"
#endif

#ifndef PROCP_FS_ROOT
#define PROCP_FS_ROOT "/proc/"
#endif

sigar_int64_t sigar_time_now_millis(void);

char *sigar_uitoa(char *buf, unsigned int n, int *len);

char *sigar_skip_token(char *p);

int sigar_file2str(const char *fname, char *buffer, int buflen);

int sigar_proc_file2str(char *buffer, int buflen,
                        sigar_pid_t pid,
                        const char *fname,
                        int fname_len);

#define SIGAR_PROC_FILE2STR(buffer, pid, fname) \
    sigar_proc_file2str(buffer, sizeof(buffer), \
                        pid, fname, SSTRLEN(fname))

#define SIGAR_SKIP_SPACE(ptr) \
    while (sigar_isspace(*ptr)) ++ptr

char *sigar_proc_filename(char *buffer, int buflen,
                          sigar_pid_t pid,
                          const char *fname, int fname_len);

/* linux + freebsd */

int sigar_mem_calc_ram(sigar_t *sigar, sigar_mem_t *mem);

#define SIGAR_DEV_PREFIX "/dev/"

typedef struct sigar_cache_entry_t sigar_cache_entry_t;

struct sigar_cache_entry_t {
    sigar_cache_entry_t *next;
    sigar_uint64_t id;
    void *value;
};

typedef struct {
    sigar_cache_entry_t **entries;
    unsigned int count, size;
    void (*free_value)(void *ptr);
} sigar_cache_t;

sigar_cache_t *sigar_cache_new(int size);

sigar_cache_entry_t *sigar_cache_get(sigar_cache_t *table,
                                     sigar_uint64_t key);

sigar_cache_entry_t *sigar_cache_find(sigar_cache_t *table,
                                      sigar_uint64_t key);

void sigar_cache_destroy(sigar_cache_t *table);

#endif /* SIGAR_UTIL_H */
