/*
 *    Copyright 2022-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include "sigar_port.h"

#ifdef WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include <cerrno>
#include <cinttypes>

static int parse_pid(char* pidstr, sigar_pid_t* result) {
    // The size and signed-ness of sigar_pid_t is different depending on the
    // system, but it is an integral type. So we use a maximum size integer
    // type to handle all systems uniformly.
    uintmax_t pid;
    char* pidend;

    errno = 0;
    pid = strtoumax(pidstr, &pidend, 10);
    if (errno != 0 || *pidend != '\0') {
        return 0;
    }

    // In general, this is incorrect, since we don't know if the value will
    // fit into the type. And there's no easy way to check that it will given
    // that we don't even know what sigar_pid_t is a typedef for. But since in
    // our case it's ns_server that passes the value, we should be fine.
    *result = (sigar_pid_t)pid;
    return 1;
}

int main(int argc, char** argv) {
#ifdef WIN32
    _setmode(1, _O_BINARY);
    _setmode(0, _O_BINARY);
#endif

    sigar_pid_t babysitter_pid;
    if (argc != 2 || !parse_pid(argv[1], &babysitter_pid)) {
        exit(1);
    }

    return sigar_port_main(babysitter_pid, stdin, stdout);
}
