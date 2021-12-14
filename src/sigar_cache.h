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

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sigar_cache_entry_t sigar_cache_entry_t;

struct sigar_cache_entry_t {
    sigar_cache_entry_t *next;
    uint64_t id;
    void *value;
};

typedef struct {
    sigar_cache_entry_t **entries;
    unsigned int count, size;
    void (*free_value)(void *ptr);
} sigar_cache_t;

sigar_cache_t *sigar_cache_new(int size);

sigar_cache_entry_t *sigar_cache_get(sigar_cache_t *table,
                                     uint64_t key);

sigar_cache_entry_t *sigar_cache_find(sigar_cache_t *table,
                                      uint64_t key);

void sigar_cache_destroy(sigar_cache_t *table);

#ifdef __cplusplus
}
#endif
