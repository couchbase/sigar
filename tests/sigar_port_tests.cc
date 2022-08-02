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
#include <folly/portability/Unistd.h>
#include <array>
#include <thread>
#include <cerrno>

#include "../programs/sigar_port.h"

TEST(SigarPort, SigarPortTest) {
#ifdef WIN32
    // For some reason it doesn't look like the pipe impl
    // from Folly works as expected.. I'm getting invalid argument
    // for fflush, fread etc
    GTEST_SKIP();
#else
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
        exitcode = sigar_port_main(getpid(), portIn, portOut);
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
#endif
}
