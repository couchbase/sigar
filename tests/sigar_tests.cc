/*
 *    Copyright 2021-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

/**
 * Copyright (c) 2009, Sun Microsystems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Sun Microsystems Inc. nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <folly/portability/GTest.h>
#include <sigar.h>
#include <thread>
#include <chrono>
#include <platform/dirutils.h>

class Sigar : public ::testing::Test {
protected:
    void SetUp() override {
        Test::SetUp();
        ASSERT_EQ(SIGAR_OK, sigar_open(&instance));
    }

    void TearDown() override {
        Test::TearDown();
        sigar_close(instance);
    }

    void createPidFileAndWait(const std::string& pids) {
        const auto pidfile = cb::io::mktemp(pids + "/pid_");
        while (cb::io::isFile(pidfile)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        exit(EXIT_SUCCESS);
    }

    sigar_t* instance = nullptr;
};

TEST_F(Sigar, test_sigar_cpu_get) {
    sigar_cpu_t cpu;
    const auto ret = sigar_cpu_get(instance, &cpu);
    ASSERT_EQ(SIGAR_OK, ret)
            << "sigar_cpu_get: " << sigar_strerror(instance, ret);
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.user);
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.sys);
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.idle);
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.wait);
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.total);
}

TEST_F(Sigar, test_sigar_mem_get) {
    sigar_mem_t mem;
    int ret = sigar_mem_get(instance, &mem);
    ASSERT_EQ(SIGAR_OK, ret)
            << "sigar_mem_get: " << sigar_strerror(instance, ret);

    EXPECT_LT(0, mem.ram);
    EXPECT_LT(0, mem.total);
    EXPECT_LT(0, mem.used);
    EXPECT_LT(0, mem.free);
    EXPECT_LT(0, mem.actual_free);
    EXPECT_LT(0, mem.actual_used);
}

TEST_F(Sigar, test_sigar_pid_get) {
    const auto pid = sigar_pid_get(instance);
    ASSERT_NE(0, pid);
}

TEST_F(Sigar, test_sigar_proc_list_get) {
    sigar_proc_list_t proclist;
    int ret = sigar_proc_list_get(instance, &proclist);
    ASSERT_EQ(SIGAR_OK, ret)
            << "sigar_proc_list_get: " << sigar_strerror(instance, ret);

    ASSERT_LT(0, proclist.number);

    for (unsigned long ii = 0; ii < proclist.number; ii++) {
        sigar_pid_t pid = proclist.data[ii];
        sigar_proc_mem_t proc_mem;
        sigar_proc_state_t proc_state;

        if (SIGAR_OK == (ret = sigar_proc_mem_get(instance, pid, &proc_mem))) {
            EXPECT_NE(SIGAR_FIELD_NOTIMPL, proc_mem.size);
            EXPECT_NE(SIGAR_FIELD_NOTIMPL, proc_mem.resident);
#if !(defined(__APPLE__) || defined(WIN32))
            // MacOS X and win32 do provide them
            EXPECT_NE(SIGAR_FIELD_NOTIMPL, proc_mem.share);
            EXPECT_NE(SIGAR_FIELD_NOTIMPL, proc_mem.minor_faults);
            EXPECT_NE(SIGAR_FIELD_NOTIMPL, proc_mem.major_faults);
#endif
#if !defined(__APPLE__)
            EXPECT_NE(SIGAR_FIELD_NOTIMPL, proc_mem.page_faults);
#endif
        } else {
            switch (ret) {
            case ESRCH:
            case EPERM:
                /* track the expected error code */
                break;
            default:
                FAIL() << "sigar_proc_mem_get: errno: " << strerror(errno)
                       << " " << sigar_strerror(instance, ret);
            }
        }

        ret = sigar_proc_state_get(instance, pid, &proc_state);
        ASSERT_EQ(SIGAR_OK, ret)
                << "sigar_proc_state_get: " << sigar_strerror(instance, ret);
        ASSERT_NE(nullptr, proc_state.name);
#ifndef __APPLE__
        EXPECT_NE(SIGAR_FIELD_NOTIMPL, proc_state.threads);
#endif
    }

    sigar_proc_list_destroy(instance, &proclist);
}

TEST_F(Sigar, test_sigar_swap_get) {
    sigar_swap_t swap;

    const auto ret = sigar_swap_get(instance, &swap);
    ASSERT_EQ(SIGAR_OK, ret)
            << "sigar_swap_get: " << sigar_strerror(instance, ret);
    ASSERT_EQ(swap.total, swap.used + swap.free);
}

#ifndef WIN32
TEST_F(Sigar, test_sigar_proc_list_get_children) {
    auto pidfile = cb::io::mkdtemp("t_pchilds_s");
    std::vector<pid_t> pids;
    // create some childs and register all of them
    for (int ii = 0; ii < 3; ++ii) {
        auto pid = fork();
        if (pid == 0) {
            // create a grandchild
            switch (fork()) {
            case 0:
                createPidFileAndWait(pidfile);
                // NOT REACHED

            case (pid_t)-1:
                perror("fork()");
                exit(EXIT_FAILURE);
            default:
                    ;
            }

            // child
            createPidFileAndWait(pidfile);
            // Not reached
        } else if (pid == -1) {
            perror("fork()");
            exit(EXIT_FAILURE);
        }
        pids.push_back(pid);
    }

    // Wait until they're all running
    std::vector<std::string> files;
    while (files.size() < 6) {
        // check if any processes died!
        files = cb::io::findFilesContaining(pidfile, "pid");
    }

    // We've got all of the processes running.. now lets check if sigar gives me
    // 6 processes
    sigar_proc_list_t proc_list;
    const auto ret = sigar_proc_list_get_children(instance, getpid(), &proc_list);
    ASSERT_EQ(SIGAR_OK, ret)
            << "sigar_proc_list_get_children: " << sigar_strerror(instance, ret);

    EXPECT_EQ(6, proc_list.number) << "I expected to get 6 childs";
    sigar_proc_list_destroy(instance, &proc_list);
    cb::io::rmrf(pidfile);
    // reap the zombies
    for (const auto pid : pids) {
        int exitcode;
        waitpid(pid, &exitcode, 0);
    }
}
#endif
