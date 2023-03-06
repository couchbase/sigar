/*
 *    Copyright 2022-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include <folly/portability/GTest.h>
#include <nlohmann/json.hpp>
#include <array>
#include <cerrno>
#include <cstdio>
#include <thread>

#include "../programs/sigar_port.h"

#ifdef WIN32
#include <fcntl.h>
#include <io.h>

#define pipe(a) _pipe(a, 8192, _O_BINARY)
#define fdopen(a, b) _fdopen(a, b)
#endif

TEST(SigarPort, SigarPortTest) {
    std::array<int, 2> fds;
    ASSERT_EQ(0, pipe(fds.data())) << strerror(errno);

    auto* portIn = fdopen(fds[0], "rb");
    auto* myOut = fdopen(fds[1], "ab");

    ASSERT_EQ(0, pipe(fds.data())) << strerror(errno);
    auto* myIn = fdopen(fds[0], "rb");
    auto* portOut = fdopen(fds[1], "ab");

    ASSERT_NE(nullptr, portIn);
    ASSERT_NE(nullptr, myIn);
    ASSERT_NE(nullptr, portOut);
    ASSERT_NE(nullptr, myOut);

    int exitcode;
    std::thread second{[&exitcode, portIn, portOut]() {
        exitcode =
                sigar_port_main(getpid(), OutputFormat::Raw, portIn, portOut);
    }};

    int cmd = 0;
    ASSERT_EQ(1, fwrite(&cmd, sizeof(cmd), 1, myOut)) << strerror(errno);
    ASSERT_EQ(0, fflush(myOut)) << strerror(errno);

    system_stats stats;
    ASSERT_EQ(1, fread(&stats, sizeof(stats), 1, myIn)) << strerror(errno);

    EXPECT_EQ(CURRENT_SYSTEM_STAT_VERSION, stats.version);

#ifdef __linux__
    EXPECT_NE(-1, stats.allocstall);
#else
    EXPECT_EQ(-1, stats.allocstall);
#endif
    // do it one more time
    ASSERT_EQ(1, fwrite(&cmd, sizeof(cmd), 1, myOut)) << strerror(errno);
    ASSERT_EQ(0, fflush(myOut)) << strerror(errno);
    ASSERT_EQ(1, fread(&stats, sizeof(stats), 1, myIn)) << strerror(errno);

    // Close the pipeline.. This will cause sigar_port thread to stop
    ASSERT_EQ(0, fclose(myOut)) << strerror(errno);
    ASSERT_EQ(0, fclose(myIn)) << strerror(errno);

    // Join the thread
    second.join();

    // Close the streams
    ASSERT_EQ(0, fclose(portIn)) << strerror(errno);
    ASSERT_EQ(0, fclose(portOut)) << strerror(errno);
    ASSERT_EQ(0, exitcode);
}

TEST(SigarPort, SigarPortTestJSON) {
    std::array<int, 2> fds;
    ASSERT_EQ(0, pipe(fds.data())) << strerror(errno);

    auto* portIn = fdopen(fds[0], "rb");
    auto* myOut = fdopen(fds[1], "ab");

    ASSERT_EQ(0, pipe(fds.data())) << strerror(errno);
    auto* myIn = fdopen(fds[0], "rb");
    auto* portOut = fdopen(fds[1], "ab");

    ASSERT_NE(nullptr, portIn);
    ASSERT_NE(nullptr, myIn);
    ASSERT_NE(nullptr, portOut);
    ASSERT_NE(nullptr, myOut);

    int exitcode;
    std::thread second{[&exitcode, portIn, portOut]() {
        exitcode =
                sigar_port_main(getpid(), OutputFormat::Json, portIn, portOut);
    }};

    fprintf(myOut, "next\n");
    fflush(myOut);

    auto getline = [](auto input) -> std::string {
        // Should receive one line with content size,
        // then content size data with JSON
        std::array<char, 80> line;
        fgets(line.data(), line.size(), input);
        auto size = std::stoul(line.data());
        EXPECT_NE(0, size);
        std::string data;
        data.resize(size);

        fread(data.data(), size, 1, input);
        return data;
    };

    const auto content1 = getline(myIn);

    // do it one more time
    fprintf(myOut, "next\n");
    fflush(myOut);

    const auto content2 = getline(myIn);

    // something should differ
    EXPECT_NE(content1, content2);

    // Close the pipeline... This will cause sigar_port thread to stop
    ASSERT_EQ(0, fclose(myOut)) << strerror(errno);
    ASSERT_EQ(0, fclose(myIn)) << strerror(errno);

    // Join the thread
    second.join();

    // Close the streams
    ASSERT_EQ(0, fclose(portIn)) << strerror(errno);
    ASSERT_EQ(0, fclose(portOut)) << strerror(errno);
    ASSERT_EQ(0, exitcode);
}

/// Due to the problems with folly's pipes on windows lets just verify
/// that the code used to get the data "works" (don't crash).
TEST(SigarPort, NextSample) {
    sigar_t* sigar;
    ASSERT_EQ(SIGAR_OK, sigar_open(&sigar));
    next_sample(sigar, sigar_pid_get(sigar));
    sigar_close(sigar);
}
