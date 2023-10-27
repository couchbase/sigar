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
#pragma once

#include <sigar/sigar.h>

#define SIGAR_STRNCPY(dest, src, len) \
    strncpy(dest, src, len);          \
    dest[len - 1] = '\0'

/* we use fixed size buffers pretty much everywhere */
/* this is strncpy + ensured \0 terminator */
#define SIGAR_SSTRCPY(dest, src) SIGAR_STRNCPY(dest, src, sizeof(dest))

#define SIGAR_MSEC 1000L
#define SIGAR_USEC SIGAR_MSEC * 1000L

struct sigar_t {
    sigar_t() : instance(sigar::SigarIface::New()) {
    }
    std::unique_ptr<sigar::SigarIface> instance;
    std::array<char, 256> errbuf;
};

// We don't want a dependency for spdlog in sigar as it is also
// used from go binaries (and all we really need is the error
// constants... Just copy in a few of them to make sure we
// can log errors from our binaries)

namespace sigar::loglevel {
enum Level : int {
    trace,
    debug,
    info,
    warn,
    err,
    critical,
};
}
