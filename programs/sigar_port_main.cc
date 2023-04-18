/*
 *    Copyright 2022-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include "sigar_port.h"

#ifdef WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#include <platform/command_line_options_parser.h>
#include <charconv>
#include <iostream>
#include <optional>
#include <string>

static sigar_pid_t parse_pid(std::string_view pidstr) {
    try {
        sigar_pid_t value{};
        const auto [ptr, ec]{std::from_chars(
                pidstr.data(), pidstr.data() + pidstr.size(), value)};
        if (ec != std::errc()) {
            if (ec == std::errc::invalid_argument) {
                throw std::invalid_argument("no conversion");
            }
            if (ec == std::errc::result_out_of_range) {
                throw std::out_of_range("value exceeds long");
            }
            throw std::system_error(std::make_error_code(ec));
        }
        if (ptr != pidstr.data() + pidstr.size()) {
            throw std::invalid_argument("invalid characters in pid string");
        }
        return value;
    } catch (const std::exception& exception) {
        std::cerr << "Failed to parse pid: " << exception.what() << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv) {
#ifdef WIN32
    _setmode(1, _O_BINARY);
    _setmode(0, _O_BINARY);
#endif

    bool snapshot = false;
    std::optional<sigar_pid_t> babysitter_pid;
    enum Option { Json, BabysitterPid, Snapshot, HumanReadable, Help };

    cb::getopt::CommandLineOptionsParser parser;
    using cb::getopt::Argument;

    parser.addOption({[&babysitter_pid](auto value) {
                          babysitter_pid = parse_pid(value);
                      },
                      "babysitter_pid",
                      Argument::Required,
                      "pid",
                      "The parent pid of all processes to report"});
    parser.addOption({[](auto) {}, "json", "Ignored"});
    parser.addOption({[&snapshot](auto) { snapshot = true; },
                      "snapshot",
                      "Dump the current information and terminate"});
    parser.addOption({[](auto) { sigar_port::human_readable_output = true; },
                      "human-readable",
                      "Print sizes in \"human readable\" form by converting to "
                      "(K/M/T/P) by using power 1024. Print times as 1h:1m:32s "
                      "(or just \"22 ms\")"});
    parser.addOption({[&parser](auto) {
                          std::cerr << "sigar_port [options]" << std::endl;
                          parser.usage(std::cerr);
                          std::exit(EXIT_SUCCESS);
                      },
                      "help",
                      "Print this help"});

    const auto arguments = parser.parse(argc, argv, [&parser]() {
        std::cerr << std::endl;
        parser.usage(std::cerr);
        std::exit(EXIT_FAILURE);
    });

    if (!babysitter_pid) {
        if (!arguments.empty()) {
            babysitter_pid = parse_pid(arguments.front());
        }
    }

    sigar_port::input = stdin;
    sigar_port::output = stdout;
    sigar_port::error = stderr;

#ifdef WIN32
    sigar_port::indentation = sigar_port::human_readable_output ? 2 : -1;
#else
    sigar_port::indentation =
            (isatty(fileno(stdout)) || isatty(fileno(stdin)) ||
             sigar_port::human_readable_output)
                    ? 2
                    : -1;
#endif

    if (snapshot) {
        return sigar_port_snapshot(babysitter_pid);
    }

    return sigar_port_main(babysitter_pid);
}
