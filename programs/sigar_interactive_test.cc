/*
 *     Copyright 2023-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

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

using namespace std::string_literals;

/**
 * sigar_test is a program one may use to help look at the statistics
 * reported from sigar.
 */
int main() {
    fprintf(stdout,
            R"(Running as process %u

Commands:
    resize <number> - Resize buffer to the provided number
    loop <seconds>  - Constantly read the clock in a loop the next
                      provided number of seconds

)",
            getpid());

    std::vector<char> vector;

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

        index = data.find(' ');
        if (index == std::string::npos) {
            fprintf(stderr, "usage: command value\n");
            continue;
        }
        auto command = data.substr(0, index);
        auto argument = data.substr(index + 1);

        try {
            if (command == "resize"s) {
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
            } else if (command == "loop") {
                auto timeout = std::chrono::steady_clock::now() +
                               std::chrono::seconds{stoi(argument)};
                while (std::chrono::steady_clock::now() < timeout) {
                    // do nothing
                }
            } else {
                fprintf(stderr, "Unknown command\n");
            }
        } catch (const std::exception& e) {
            fprintf(stderr, "Error: %s\n", e.what());
        }
    }

    return EXIT_SUCCESS;
}
