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

#include <boost/filesystem.hpp>
#include <folly/portability/GTest.h>
#include <nlohmann/json.hpp>
#include <platform/dirutils.h>
#include <platform/platform_thread.h>
#include <platform/process_monitor.h>
#include <platform/timeutils.h>
#include <sigar.h>
#include <sigar_control_group.h>
#include <chrono>
#include <thread>

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

TEST_F(Sigar, test_sigar_swap_get) {
    sigar_swap_t swap;

    const auto ret = sigar_swap_get(instance, &swap);
    ASSERT_EQ(SIGAR_OK, ret)
            << "sigar_swap_get: " << sigar_strerror(instance, ret);
    ASSERT_EQ(swap.total, swap.used + swap.free);
}

TEST_F(Sigar, test_sigar_proc_list_get_children) {
    auto binary = boost::filesystem::current_path() / "sigar_tests_child";
    auto directory = boost::filesystem::path(
            cb::io::mkdtemp((boost::filesystem::current_path() / "sigar_tests")
                                    .generic_string()));
    std::vector<std::string> cmdline = {{binary.generic_string(),
                                         "--directory",
                                         directory.generic_string(),
                                         "--create-child=5"}};
    auto child = ProcessMonitor::create(cmdline, [](const auto&) {});

    // Wait until they're all running
    std::vector<std::string> files;
    while (files.size() < 6) {
        // check if any processes died!
        files = cb::io::findFilesContaining(directory.generic_string(), "pid");
    }

    // We've got all of the processes running.. now lets check if sigar gives me
    // 6 processes
    std::vector<sigar_pid_t> pids;
    sigar::iterate_child_processes(
            instance,
            getpid(),
            [&pids](auto pid, auto ppid, auto starttime, auto name) {
                EXPECT_EQ(pids.end(), std::find(pids.begin(), pids.end(), pid))
                        << "The process should not be reported twice";
                pids.push_back(pid);
            });
    EXPECT_EQ(6, pids.size()) << "I expected to get 6 childs";

    for (const auto& pid : pids) {
        sigar_proc_mem_t proc_mem;
        sigar_proc_state_t proc_state;
        int ret;

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

    remove_all(directory);

    while (child->isRunning()) {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    // Make sure we get time to reap the process...
    std::this_thread::sleep_for(std::chrono::milliseconds{10});

    pids.clear();
    sigar::iterate_child_processes(
            instance,
            getpid(),
            [&pids](auto pid, auto ppid, auto starttime, auto name) {
                pids.push_back(pid);
            });
    EXPECT_TRUE(pids.empty()) << "I expected all childs to be gone!";
}

TEST_F(Sigar, sigar_get_control_group_info) {
    sigar_control_group_info_t info;
    sigar_get_control_group_info(&info);

#ifdef __linux__
    ASSERT_EQ(1, info.supported);
    ASSERT_TRUE((info.version == 1) || (info.version == 2));
    ASSERT_NE(0, info.num_cpu_prc);

    // cgroup V2 returns "max" if no limit is set
    if (info.memory_max > 0) {
        ASSERT_LE(info.memory_current, info.memory_max);
    } else {
        EXPECT_EQ(2, info.version);
    }

    EXPECT_NE(0, info.memory_current);
    EXPECT_NE(0, info.usage_usec);
    EXPECT_NE(0, info.user_usec);
    EXPECT_NE(0, info.system_usec);
#else
    ASSERT_EQ(0, info.supported);
#endif
}

#ifdef __linux__
TEST_F(Sigar, test_sigar_proc_state_get) {
    sigar_proc_state_t proc_state;
    auto ret = sigar_proc_state_get(instance, getpid(), &proc_state);
    ASSERT_EQ(SIGAR_OK, ret)
            << "sigar_proc_state_get: " << sigar_strerror(instance, ret);
    ASSERT_NE(nullptr, proc_state.name);
    EXPECT_EQ(1, proc_state.threads);
    std::thread second{[&proc_state, &ret, i = instance]() {
        ret = sigar_proc_state_get(i, getpid(), &proc_state);
    }};
    second.join();
    ASSERT_EQ(SIGAR_OK, ret);
    EXPECT_EQ(2, proc_state.threads);
}

class MockSigar : public Sigar {
public:
    static void SetUpTestCase() {
        sigar_set_procfs_root(SOURCE_ROOT);
    }

    static void TearDownTestCase() {
        sigar_set_procfs_root(nullptr);
    }
};

TEST_F(MockSigar, MB49911) {
    sigar_cpu_t cpu;
    EXPECT_EQ(SIGAR_OK, sigar_cpu_get(instance, &cpu));
    EXPECT_EQ(88917270, cpu.user);
    EXPECT_EQ(11349280, cpu.sys);
    EXPECT_EQ(240, cpu.nice);
    EXPECT_EQ(7945213060, cpu.idle);
    EXPECT_EQ(1651470, cpu.wait);
    EXPECT_EQ(0, cpu.irq);
    EXPECT_EQ(209860, cpu.soft_irq);
    EXPECT_EQ(0, cpu.stolen);
    EXPECT_EQ(8047341180, cpu.total);
}

TEST_F(MockSigar, test_sigar_proc_mem_get) {
    sigar_proc_mem_t procmem;
    ASSERT_EQ(SIGAR_OK, sigar_proc_mem_get(instance, 66666666, &procmem));

    EXPECT_EQ(11762167808, procmem.size);
    EXPECT_EQ(3729625088, procmem.resident);
    EXPECT_EQ(437837824, procmem.share);
    EXPECT_EQ(27177033, procmem.minor_faults);
    EXPECT_EQ(115493, procmem.major_faults);
    EXPECT_EQ(27292526, procmem.page_faults);
}

TEST_F(MockSigar, test_sigar_swap_get) {
    sigar_swap_t swap;
    ASSERT_EQ(SIGAR_OK, sigar_swap_get(instance, &swap));
    EXPECT_EQ(1023406080, swap.total);
    EXPECT_EQ(0, swap.used);
    EXPECT_EQ(1023406080, swap.free);
    EXPECT_EQ(0, swap.page_in);
    EXPECT_EQ(0, swap.page_out);
    EXPECT_EQ(SIGAR_FIELD_NOTIMPL, swap.allocstall);
    EXPECT_EQ(0, swap.allocstall_dma);
    EXPECT_EQ(0, swap.allocstall_dma32);
    EXPECT_EQ(0, swap.allocstall_normal);
    EXPECT_EQ(0, swap.allocstall_movable);
    ASSERT_EQ(swap.total, swap.used + swap.free);
}

TEST_F(MockSigar, test_sigar_mem_get) {
    sigar_mem_t mem;
    ASSERT_EQ(SIGAR_OK, sigar_mem_get(instance, &mem));
    EXPECT_EQ(31744, mem.ram);
    EXPECT_EQ(33283383296, mem.total);
    EXPECT_EQ(19910578176, mem.used);
    EXPECT_EQ(13372805120, mem.free);
    EXPECT_EQ(9683591168, mem.actual_used);
    EXPECT_EQ(23599792128, mem.actual_free);
    EXPECT_EQ(29, int(mem.used_percent));
    EXPECT_EQ(70, int(mem.free_percent));
}

TEST_F(MockSigar, sigar_proc_state_get) {
    sigar_proc_state_t ps;

    ASSERT_EQ(SIGAR_OK, sigar_proc_state_get(instance, 66666666, &ps));
    EXPECT_STREQ("java  vm", ps.name);
    EXPECT_EQ('S', ps.state);
    EXPECT_EQ(10563, ps.ppid);
    EXPECT_EQ(1026, ps.tty);
    EXPECT_EQ(20, ps.priority);
    EXPECT_EQ(0, ps.nice);
    EXPECT_EQ(4, ps.processor);
    EXPECT_EQ(91, ps.threads);
}

#endif
