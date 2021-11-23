/*
 * Copyright (c) 2007-2008 Hyperic, Inc.
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

#ifndef SIGAR_FORMAT_H
#define SIGAR_FORMAT_H

typedef struct {
    double user;
    double sys;
    double nice;
    double idle;
    double wait;
    double irq;
    double soft_irq;
    double stolen;
    double combined;
} sigar_cpu_perc_t;

SIGAR_DECLARE(int) sigar_cpu_perc_calculate(sigar_cpu_t *prev,
                                            sigar_cpu_t *curr,
                                            sigar_cpu_perc_t *perc);

SIGAR_DECLARE(int) sigar_uptime_string(sigar_t *sigar,
                                       sigar_uptime_t *uptime,
                                       char *buffer,
                                       int buflen);

SIGAR_DECLARE(char *) sigar_format_size(sigar_uint64_t size, char *buf);
#endif
