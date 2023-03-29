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
#include <nlohmann/json.hpp>
#include <platform/platform_thread.h>
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
#ifdef WIN32
    EXPECT_EQ(SIGAR_FIELD_NOTIMPL, cpu.nice);
#else
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.nice);
#endif

#if defined(WIN32) || defined(__APPLE__)
    EXPECT_EQ(SIGAR_FIELD_NOTIMPL, cpu.wait);
    EXPECT_EQ(SIGAR_FIELD_NOTIMPL, cpu.stolen);
    EXPECT_EQ(SIGAR_FIELD_NOTIMPL, cpu.irq);
    EXPECT_EQ(SIGAR_FIELD_NOTIMPL, cpu.soft_irq);
#else
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.wait);
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.stolen);
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.irq);
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.soft_irq);
#endif
    EXPECT_NE(SIGAR_FIELD_NOTIMPL, cpu.total);
}

TEST_F(Sigar, test_sigar_mem_get) {
    sigar_mem_t mem;
    int ret = sigar_mem_get(instance, &mem);
    ASSERT_EQ(SIGAR_OK, ret)
            << "sigar_mem_get: " << sigar_strerror(instance, ret);

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

TEST_F(Sigar, iterate_process_threads_self) {
    std::atomic_bool isrunning{false};
    std::atomic_bool shouldstop{false};
    std::thread mythread{[&isrunning, &shouldstop]() {
        cb_set_thread_name("my-thread-name");
        isrunning = true;
        while (!shouldstop) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
    }};

    // wait for the thread to start..
    while (!isrunning) {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    // thread is running. Iterate over all threads and look for the one
    bool found;
    try {
        int callbacks = 0;
        sigar::iterate_threads(
                [&callbacks, &found](
                        auto tid, auto name, auto user, auto system) {
                    ++callbacks;
                    if (name == "my-thread-name") {
                        found = true;
                    }
                });
        EXPECT_NE(0, callbacks) << "Expected at least 1 thread to be found";
    } catch (const std::exception& e) {
        FAIL() << "Got exception: " << e.what();
    }
#ifndef WIN32
    EXPECT_TRUE(found) << "Failed to locate the thread to search for";
#endif
    shouldstop = true;
    mythread.join();
}

#ifdef __linux__
TEST_F(Sigar, test_sigar_proc_state_get) {
    sigar_proc_state_t proc_state;
    auto ret = sigar_proc_state_get(instance, getpid(), &proc_state);
    ASSERT_EQ(SIGAR_OK, ret)
            << "sigar_proc_state_get: " << sigar_strerror(instance, ret);
    ASSERT_NE(nullptr, proc_state.name);
    EXPECT_EQ(1, proc_state.threads);

    std::thread second{[]() {
        sigar_t* instance;
        ASSERT_EQ(SIGAR_OK, sigar_open(&instance));
        sigar_proc_state_t proc_state;
        EXPECT_EQ(SIGAR_OK,
                  sigar_proc_state_get(instance, getpid(), &proc_state));
        sigar_close(instance);
        EXPECT_EQ(2, proc_state.threads);
    }};
    second.join();
}
#endif
