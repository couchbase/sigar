/*
 *     Copyright 2023-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include <sigar/sigar.h>
#include <system_error>

namespace sigar {

extern std::unique_ptr<SigarIface> NewAppleSigar();
extern std::unique_ptr<SigarIface> NewLinuxSigar();
extern std::unique_ptr<SigarIface> NewWin32Sigar();

std::unique_ptr<SigarIface> SigarIface::New(Backend backend) {
    switch (backend) {
    case Backend::Native:
#ifdef __APPLE__
        return NewAppleSigar();
#elif defined(__linux__)
        return NewLinuxSigar();
#else
        return NewWin32Sigar();
#endif
    case Backend::Apple:
        return NewAppleSigar();

    case Backend::Linux:
        return NewLinuxSigar();

    case Backend::Windows:
        return NewWin32Sigar();
    }
    throw std::invalid_argument("SigarIface::New: Unknown backend");
}

SigarIface::SigarIface() = default;

} // namespace sigar
