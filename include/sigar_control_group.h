/*
 *    Copyright 2021-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#pragma once

#include <sigar/types.h>
#include <sigar_visibility.h>

#ifdef __cplusplus
extern "C" {
#endif

SIGAR_PUBLIC_API void sigar_get_control_group_info(sigar_control_group_info_t*);

#ifdef __cplusplus
}
#endif
