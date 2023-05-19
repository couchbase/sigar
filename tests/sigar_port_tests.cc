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

    sigar_port::input = portIn;
    sigar_port::output = portOut;

    int exitcode;
    std::thread second{[&exitcode]() { exitcode = sigar_port_main(getpid()); }};

    fprintf(myOut, "next\n");
    fflush(myOut);

    auto getline = [](auto input) -> nlohmann::json {
        // Should receive one line with content size,
        // then content size data with JSON
        std::array<char, 80> line;
        fgets(line.data(), line.size(), input);
        auto size = std::stoul(line.data());
        EXPECT_NE(0, size);
        std::string data;
        data.resize(size);

        fread(data.data(), size, 1, input);
        return nlohmann::json::parse(data);
    };

    const auto content1 = getline(myIn);
    EXPECT_FALSE(content1.empty());

    // do it one more time
    fprintf(myOut, "next\n");
    fflush(myOut);

    const auto content2 = getline(myIn);
    EXPECT_FALSE(content2.empty());

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
