/*
 *     Copyright 2019 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */


#include <sigar.h>
#include <platform/dirutils.h>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <thread>

void createPidFileAndWait(const std::string& pids) {
    const auto pidfile = cb::io::mktemp(pids + "/pid_");
    while (cb::io::isFile(pidfile)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    auto pids = cb::io::mkdtemp("t_pchilds_s");
    // create some childs and register all of them
    for (int ii = 0; ii < 3; ++ii) {
        auto pid = fork();
        if (pid == 0) {
            // create a grandchild
            switch (fork()) {
                case 0:
                    createPidFileAndWait(pids);
                 // NOT REACHED

                case (pid_t)-1:
                    perror("fork()");
                    exit(EXIT_FAILURE);
                default:
                    ;
            }

            // child
            createPidFileAndWait(pids);
            // Not reached
        } else if (pid == -1) {
            perror("fork()");
            exit(EXIT_FAILURE);
        }
    }

    // Wait until they're all running
    std::vector<std::string> files;
    while (files.size() < 6) {
        // check if any processes died!
        files = cb::io::findFilesContaining(pids, "pid");
    }

    // We've got all of the processes running.. now lets check if sigar gives me
    // 6 processes

    sigar_t* sigar;
    if (sigar_open(&sigar) != SIGAR_OK) {
        fprintf(stderr, "Failed to initialize sigar\n");
        return 1;
    }

    sigar_proc_list_t proc_list;
    if (sigar_proc_list_get_children(sigar, getpid(), &proc_list) !=
        SIGAR_OK) {
        fprintf(stderr, "Failed to fetch childrens\n");
        return 1;
    }

    int status = EXIT_SUCCESS;
    if (proc_list.number != 6) {
        fprintf(stderr, "I expected to get 6 childs\n");
        status = EXIT_FAILURE;
    }

    sigar_proc_list_destroy(sigar, &proc_list);
    sigar_close(sigar);

    cb::io::rmrf(pids);
    exit(status);
}
