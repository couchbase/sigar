/*
 *    Copyright 2021-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include <getopt.h>
#include <platform/process_monitor.h>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <thread>
#include <vector>

#ifdef WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

int main(int argc, char** argv) {
    int cmd;
    int num_childs = 0;
    std::filesystem::path directory;
    std::unique_ptr<ProcessMonitor> child;

    const std::vector<option> options = {
            {"directory", required_argument, nullptr, 'd'},
            {"create-child", required_argument, nullptr, 'c'},
            {"help", no_argument, nullptr, 0},
            {nullptr, 0, nullptr, 0}};

    while ((cmd = getopt_long(argc, argv, "", options.data(), nullptr)) !=
           EOF) {
        switch (cmd) {
        case 'd':
            directory = optarg;
            if (!is_directory(directory)) {
                std::cerr << directory.generic_string() << " is not a directory"
                          << std::endl;
                return EXIT_FAILURE;
            }
            break;
        case 'c':
            num_childs = std::atoi(optarg);
            break;
        default:
            std::cerr << R"(usage: sigar_test_child [options]
options:
   --directory=/dir        Directory create the pid file in and to wait for
                           until exiting.
   --create-child=[number] The depth of the process tree to create

)";
            return EXIT_FAILURE;
        }
    }

    if (directory.empty()) {
        std::cerr << "Directory must be specified with --directory"
                  << std::endl;
        return EXIT_FAILURE;
    }

    // Create the child process if we want
    if (num_childs > 0) {
        std::vector<std::string> cmdline = {{argv[0],
                                             "--directory",
                                             directory.generic_string(),
                                             "--create-child",
                                             std::to_string(--num_childs)}};
        child = ProcessMonitor::create(cmdline, [](const auto& ec) {});
    }

    const auto pidfile =
            directory / std::filesystem::path(std::string{"pid_"} +
                                                std::to_string(getpid()));
    if (std::filesystem::exists(pidfile)) {
        std::cerr << pidfile.generic_string() << " exists!" << std::endl;
        return EXIT_FAILURE;
    }

    FILE* fp = fopen(pidfile.generic_string().c_str(), "w");
    if (!fp) {
        std::cerr << "Failed to create " << pidfile.generic_string()
                  << std::endl;
        return EXIT_FAILURE;
    }
    fclose(fp);

    while (exists(pidfile)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // wait for the child to stop
    if (child) {
        while (child->isRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
    }

    return EXIT_SUCCESS;
}
