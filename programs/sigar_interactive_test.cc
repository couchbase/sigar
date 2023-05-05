/*
 *     Copyright 2023-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include "sigar_port.h"

#include <platform/split_string.h>
#include <array>
#include <chrono>
#include <cstring>
#include <string>
#include <vector>

#ifdef WIN32
#include <process.h>
#define getpid() _getpid()
#else
#include <unistd.h>
#endif

using namespace std::string_view_literals;

std::vector<char> vector;

static void resize(std::vector<std::string_view>& arguments) {
    if (arguments.size() != 2) {
        fprintf(stderr, "Usage: resize <size>\n");
        return;
    }
    std::string argument{arguments[1]};
    auto val = std::stoul(argument);
    if (argument.find_first_of("kK") != std::string::npos) {
        val *= 1024;
    } else if (argument.find_first_of("mM") != std::string::npos) {
        val *= 1024 * 1024;
    } else if (argument.find_first_of("gG") != std::string::npos) {
        val *= 1024 * 1024 * 1024;
    }
    vector.resize(val);
    vector.shrink_to_fit();
    std::fill(vector.begin(), vector.end(), 'a');
}

static void loop(std::vector<std::string_view>& arguments) {
    if (arguments.size() != 2) {
        fprintf(stderr, "Usage: loop <seconds>\n");
        return;
    }
    std::string argument{arguments[1]};

    auto timeout = std::chrono::steady_clock::now() +
                   std::chrono::seconds{stoi(argument)};
    while (std::chrono::steady_clock::now() < timeout) {
        // do nothing
    }
}

static void readFile(std::vector<std::string_view>& arguments) {
    if (arguments.size() != 2) {
        fprintf(stderr, "Usage: read <filename>\n");
        return;
    }
    std::string argument{arguments[1]};
    if (vector.empty()) {
        fprintf(stderr,
                "Resize the vector to the size of chunks you want "
                "to read\n");
        return;
    }
    FILE* fp = fopen(argument.c_str(), "r");
    if (fp) {
        while (!ferror(fp) && !feof(fp)) {
            (void)fread(vector.data(), 1, vector.size(), fp);
        }
        fclose(fp);
    } else {
        perror("Failed to open file");
    }
}

static void snapshot(std::vector<std::string_view>& arguments) {
    if (arguments.size() != 1) {
        fprintf(stderr, "Usage: snapshot\n");
        return;
    }
    sigar_port_snapshot(getpid());
    fprintf(stdout, "\n");
}

static void help() {
    fprintf(stdout,
            R"(Commands:
    resize <number> - Resize buffer to the provided number
    loop <seconds>  - Constantly read the clock in a loop the next
                      provided number of seconds
    read <filename> - Read the named file (and discard the output)
    snapshot        - Dump the sigar_port snapshot
    help            - This help text
    quit            - End program

)");
}

/**
 * sigar_test is a program one may use to help look at the statistics
 * reported from sigar.
 */
int main() {
    fprintf(stdout, "Running as process %u\n\n", getpid());
    help();

    sigar_port::input = stdin;
    sigar_port::output = stdout;
    sigar_port::error = stderr;
    sigar_port::indentation = 2;

    while (!feof(stdin)) {
        fprintf(stdout, "Enter command> ");
        fflush(stdout);

        std::array<char, 80> line;
        if (fgets(line.data(), line.size(), stdin) == nullptr ||
            ferror(stdin) || strstr(line.data(), "quit") != nullptr) {
            break;
        }

        std::string data = line.data();
        auto index = data.find_first_of("\r\n");
        if (index != std::string::npos) {
            data.resize(index);
        }
        auto arguments = cb::string::split(data);
        if (arguments.empty()) {
            help();
            continue;
        }

        try {
            if (arguments.front() == "resize"sv) {
                resize(arguments);
            } else if (arguments.front() == "loop"sv) {
                loop(arguments);
            } else if (arguments.front() == "read"sv) {
                readFile(arguments);
            } else if (arguments.front() == "snapshot"sv) {
                snapshot(arguments);
            } else if (arguments.front() == "help"sv) {
                help();
            } else {
                fprintf(stderr, "Unknown command\n");
            }
        } catch (const std::exception& e) {
            fprintf(stderr, "Error: %s\n", e.what());
        }
    }

    return EXIT_SUCCESS;
}
