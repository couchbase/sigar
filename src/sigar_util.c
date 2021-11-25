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

#include "sigar.h"
#include "sigar_private.h"
#include "sigar_util.h"

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

#ifndef WIN32
#include <sys/time.h>
sigar_int64_t sigar_time_now_millis(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((tv.tv_sec * SIGAR_USEC) + tv.tv_usec) / SIGAR_MSEC;
}
#endif
