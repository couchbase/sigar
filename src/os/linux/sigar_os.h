/*
 * Copyright (c) 2004-2008 Hyperic, Inc.
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

#include "sigar.h"
#include "sigar_private.h"

typedef struct {
    sigar_pid_t pid;
    time_t mtime;
    uint64_t vsize;
    uint64_t rss;
    uint64_t minor_faults;
    uint64_t major_faults;
    uint64_t ppid;
    int tty;
    int priority;
    int nice;
    uint64_t start_time;
    uint64_t utime;
    uint64_t stime;
    char name[SIGAR_PROC_NAME_LEN];
    char state;
    int processor;
} linux_proc_stat_t;

struct sigar_t {
    SIGAR_T_BASE;
    int pagesize;
    int ram;
    linux_proc_stat_t last_proc_stat;
};
