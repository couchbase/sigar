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

#include <getopt.h>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

static sigar_pid_t parse_pid(const std::string& pidstr) {
    try {
        const auto result = std::stoul(pidstr);
        return sigar_pid_t(result);
    } catch (const std::exception&) {
        std::cerr << "Failed to parse pid" << std::endl;
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

    const std::vector<option> options{
            {{"json", no_argument, nullptr, Option::Json},
             {"babysitter_pid",
              required_argument,
              nullptr,
              Option::BabysitterPid},
             {"snapshot", no_argument, nullptr, Option::Snapshot},
             {"human-readable", no_argument, nullptr, Option::HumanReadable},
             {"help", no_argument, nullptr, Option::Help},
             {nullptr, 0, nullptr, 0}}};

    int cmd;
    while ((cmd = getopt_long(argc, argv, "", options.data(), nullptr)) !=
           EOF) {
        switch (cmd) {
        case Option::Json:
            // Ignored (no longer used as the default is JSON)
            break;
        case Option::BabysitterPid:
            babysitter_pid = parse_pid(optarg);
            break;
        case Option::Snapshot:
            snapshot = true;
            break;
        case Option::HumanReadable:
            sigar_port::human_readable_output = true;
            break;
        case Option::Help:
        default:
            std::cerr << "Usage: " << argv[0] << R"( [options]

Options:
   --human-readable         Print sizes in "human readable" form by
                            converting to (K/M/T/P) by using power 1024
                            Print times as 1h:1m:32s (or just "22 ms")
   --snapshot               Dump the current information and terminate
   --json                   Ignored
   --babysitter_pid=<pid>   The parent pid of all processes to report

)";
            exit(EXIT_FAILURE);
        }
    }

    if (!babysitter_pid) {
        // no pid provided through getopt...
        if (optind < argc) {
            babysitter_pid = parse_pid(argv[optind]);
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
