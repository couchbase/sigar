/*
 *    Copyright 2021-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include <sigar.h>
#include <sigar/sigar.h>
#include <sigar_control_group.h>
#include <exception>
#include <iostream>

void sigar_get_control_group_info(sigar_control_group_info_t* info) {
    try {
        *info = sigar::SigarIface::New()->get_control_group_info();
    } catch (const std::exception& exception) {
        std::cerr << "sigar_get_control_group_info(): exception: "
                  << exception.what() << std::endl;
        info->supported = 0;
    }
}
