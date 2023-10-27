/*
 *     Copyright 2023-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#pragma once

#include <functional>
#include <string_view>

namespace sigar {

/**
 * Set a callback function to receive log information produced by
 * the library.
 *
 * @param level The minimum level to log
 * @param callback The callback function to call with each log message
 */
void set_log_callback(int level,
                      std::function<void(int, std::string_view)> callback);

/**
 * Utility function to put messages into the sigar log from outside the
 * library
 *
 * @param level The type of log message
 * @param message The message to log
 */
void logit(int level, std::string_view message);
} // namespace sigar