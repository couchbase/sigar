/*
 *    Copyright 2021-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */
#include "platform/platform_thread.h"
#include <boost/filesystem.hpp>
#include <folly/portability/GTest.h>
#include <platform/dirutils.h>
#include <platform/process_monitor.h>
#include <sigar/sigar.h>
#include <chrono>
#include <thread>

using namespace sigar;

class NativeSigar : public ::testing::Test {
public:
    void SetUp() override {
        Test::SetUp();
        instance = SigarIface::New();
    }

    std::unique_ptr<SigarIface> instance;
};

TEST_F(NativeSigar, iterate_child_processes) {
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
    instance->iterate_child_processes(
            getpid(),
            [&pids, inst = instance.get()](
                    auto pid, auto ppid, auto starttime, auto name) {
                EXPECT_EQ(pids.end(), std::find(pids.begin(), pids.end(), pid))
                        << "The process should not be reported twice";
                pids.push_back(pid);

                const auto pcpu = inst->get_proc_cpu(pid);
                EXPECT_EQ(pcpu.start_time, starttime);
            });
    EXPECT_EQ(6, pids.size()) << "I expected to get 6 childs";

    for (const auto& pid : pids) {
        try {
            const auto proc_mem = instance->get_proc_memory(pid);
            EXPECT_NE(std::numeric_limits<uint64_t>::max(), proc_mem.size);
            EXPECT_NE(std::numeric_limits<uint64_t>::max(), proc_mem.resident);
#if !(defined(__APPLE__) || defined(WIN32))
            // MacOS X and win32 do provide them
            EXPECT_NE(std::numeric_limits<uint64_t>::max(), proc_mem.share);
            EXPECT_NE(std::numeric_limits<uint64_t>::max(),
                      proc_mem.minor_faults);
            EXPECT_NE(std::numeric_limits<uint64_t>::max(),
                      proc_mem.major_faults);
#endif
#if !defined(__APPLE__)
            EXPECT_NE(std::numeric_limits<uint64_t>::max(),
                      proc_mem.page_faults);
#endif
        } catch (const std::exception& e) {
            FAIL() << e.what();
        }

        try {
            const auto proc_state = instance->get_proc_state(pid);
            ASSERT_NE(nullptr, proc_state.name);
#ifndef __APPLE__
            EXPECT_NE(std::numeric_limits<uint64_t>::max(), proc_state.threads);
#endif
        } catch (const std::exception& exception) {
            FAIL() << exception.what();
        }
    }

    // https://developercommunity.visualstudio.com/t/stdfilesystemremove-doesnt-work-under-windows-10-1/398243
    // We don't support that old windows versions, but unfortunately at least
    // one of the CV builders is using Windows 1607 which have that error.
    // so lets' use cb::io::rmrf instead of remove_all(directory);
    cb::io::rmrf(directory.generic_string());

    while (child->isRunning()) {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    // Make sure we get time to reap the process...
    std::this_thread::sleep_for(std::chrono::milliseconds{10});

    pids.clear();
    instance->iterate_child_processes(
            getpid(), [&pids](auto pid, auto ppid, auto starttime, auto name) {
                pids.push_back(pid);
            });
    EXPECT_TRUE(pids.empty()) << "I expected all childs to be gone!";
}

TEST_F(NativeSigar, iterate_process_threads_self) {
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
        instance->iterate_threads(
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

TEST_F(NativeSigar, get_disk_stats) {
#ifdef __APPLE__
    // Lacking a MacOS implementation means that this test doesn't work
    GTEST_SKIP();
#endif

    std::vector<sigar::disk_usage_t> usages;
    instance->iterate_disks([&usages](auto diskUsage) {
        usages.push_back(diskUsage);
        EXPECT_NE("", diskUsage.name);
        // Not checking any individual stats here as they may not necessarily
        // be non-zero.
    });

    EXPECT_NE(0, usages.size());
}

#ifndef WIN32
class MockSigar : public ::testing::Test {
public:
    void SetUp() override {
        Test::SetUp();
        instance = SigarIface::New(Backend::Linux);
    }

    static void SetUpTestCase() {
        SigarIface::set_mock_root(SOURCE_ROOT);
    }

    static void TearDownTestCase() {
        SigarIface::set_mock_root({});
    }

    std::unique_ptr<SigarIface> instance;
};

TEST_F(MockSigar, MB49911) {
    const auto cpu = instance->get_cpu();
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
    const auto procmem = instance->get_proc_memory(66666666);
    EXPECT_EQ(11762167808, procmem.size);
    EXPECT_EQ(3729625088, procmem.resident);
    EXPECT_EQ(437837824, procmem.share);
    EXPECT_EQ(27177033, procmem.minor_faults);
    EXPECT_EQ(115493, procmem.major_faults);
    EXPECT_EQ(27292526, procmem.page_faults);
}

TEST_F(MockSigar, test_sigar_swap_get) {
    const auto swap = instance->get_swap();
    EXPECT_EQ(1023406080, swap.total);
    EXPECT_EQ(0, swap.used);
    EXPECT_EQ(1023406080, swap.free);
    EXPECT_EQ(0, swap.page_in);
    EXPECT_EQ(0, swap.page_out);
    EXPECT_EQ(0, swap.allocstall);
    ASSERT_EQ(swap.total, swap.used + swap.free);
}

TEST_F(MockSigar, test_sigar_mem_get) {
    const auto mem = instance->get_memory();
    EXPECT_EQ(33283383296, mem.total);
    EXPECT_EQ(19910578176, mem.used);
    EXPECT_EQ(13372805120, mem.free);
    EXPECT_EQ(10057596928, mem.actual_used);
    EXPECT_EQ(23225786368, mem.actual_free);
}

TEST_F(MockSigar, sigar_proc_state_get) {
    const auto ps = instance->get_proc_state(66666666);
    EXPECT_STREQ("java  vm", ps.name);
    EXPECT_EQ(10563, ps.ppid);
    EXPECT_EQ(91, ps.threads);
}

TEST_F(MockSigar, sigar_get_disk_stats) {
    std::vector<sigar::disk_usage_t> usages;
    instance->iterate_disks(
            [&usages](auto diskUsage) { usages.push_back(diskUsage); });

    static const auto sigar_sector_size = 512;

    ASSERT_EQ(2, usages.size());
    EXPECT_EQ("sdb", usages[0].name);
    EXPECT_EQ(74827222, usages[0].reads);
    EXPECT_EQ(2425492092 * sigar_sector_size, usages[0].rbytes);
    EXPECT_EQ(std::chrono::milliseconds(2544780192), usages[0].rtime);
    EXPECT_EQ(2100800967, usages[0].writes);
    EXPECT_EQ(87795119921 * sigar_sector_size, usages[0].wbytes);
    EXPECT_EQ(std::chrono::milliseconds(4282901220), usages[0].wtime);

    EXPECT_EQ(0, usages[0].queue);
    EXPECT_EQ(25, usages[0].queue_depth);
    EXPECT_EQ(std::chrono::milliseconds(3312412208), usages[0].time);

    EXPECT_EQ("sdb1", usages[1].name);
    EXPECT_EQ(15511, usages[1].reads);
    EXPECT_EQ(908156 * sigar_sector_size, usages[1].rbytes);
    EXPECT_EQ(std::chrono::milliseconds(19824), usages[1].rtime);
    EXPECT_EQ(0, usages[1].writes);
    EXPECT_EQ(0 * sigar_sector_size, usages[1].wbytes);
    EXPECT_EQ(std::chrono::milliseconds(0), usages[1].wtime);

    EXPECT_EQ(0, usages[1].queue);
    EXPECT_EQ(std::chrono::milliseconds(19792), usages[1].time);
    EXPECT_EQ(std::numeric_limits<uint64_t>::max(), usages[1].queue_depth);
}
#endif
