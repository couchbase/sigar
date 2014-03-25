/**
 * Copyright (c) 2009, Sun Microsystems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
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
#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#if defined(_WIN32)
#include <WinError.h>
#endif

#include "sigar.h"
#include "sigar_private.h"
#include "sigar_format.h"
#include "sigar_tests.h"

static char *given_path;

TEST(test_sigar_disk_stats) {
    sigar_file_system_list_t fslist;
    sigar_disk_usage_t dsu;
    size_t i;
    int best_match = 0;

    if (!given_path) {
        given_path = "";
    }

    memset(&dsu, 0, sizeof(sigar_disk_usage_t));
    assert(SIGAR_OK == sigar_file_system_list_get(t, &fslist));
    assert(fslist.number > 0);

    for (i = 0; i < fslist.number; i++) {
        sigar_file_system_t fs = fslist.data[i];
        sigar_file_system_usage_t fsusage;
        sigar_disk_usage_t diskusage;
        int ret;

        assert(fs.dir_name);
        assert(fs.dev_name);
        assert(fs.type_name);
        assert(fs.sys_type_name);
        assert(fs.type);

        if (SIGAR_OK != (ret = sigar_file_system_ping(t, &fs))) {
            continue;
        }

        if (SIGAR_OK == (ret = sigar_file_system_usage_get(t, fs.dir_name, &fsusage))) {
            if (!given_path[0]) {
                fprintf(stdout, "DirName=%s, ", fs.dir_name);
            }
            assert(IS_IMPL_U64(fsusage.total));
            assert(IS_IMPL_U64(fsusage.free));
            assert(IS_IMPL_U64(fsusage.used));
            assert(IS_IMPL_U64(fsusage.avail));
#if !(defined(SIGAR_TEST_OS_SOLARIS) || defined(_WIN32))
            /* solaris 8 */
            assert(IS_IMPL_U64(fsusage.files));
#endif
            assert(fsusage.use_percent >= 0);
        } else {
            switch (ret) {
                /* track the expected error code */
#if defined(_WIN32)
            case ERROR_NOT_READY:
                break;
#endif
            default:
                fprintf(stderr, "sigar_file_system_usage_get(%s) ret = %d (%s)\n",
                        fs.dir_name,
                        ret, sigar_strerror(t, ret));
                assert(ret == SIGAR_OK);
                break;
            }
        }

        if (SIGAR_OK == (ret = sigar_disk_usage_get(t, fs.dev_name, &diskusage))) {
            assert(IS_IMPL_U64(diskusage.reads));
            assert(IS_IMPL_U64(diskusage.writes));
#if !defined(SIGAR_TEST_OS_DARWIN)
            /* freebsd */
            assert(IS_IMPL_U64(diskusage.read_bytes));
            assert(IS_IMPL_U64(diskusage.write_bytes));
            assert(IS_IMPL_U64(diskusage.rtime));
            assert(IS_IMPL_U64(diskusage.wtime));
#endif
#if !(defined(SIGAR_TEST_OS_LINUX) || defined(SIGAR_TEST_OS_DARWIN) || defined(_WIN32))
            /* depending on the Linux version they might not be set */
            assert(IS_IMPL_U64(diskusage.qtime));
#endif
#if !(defined(SIGAR_TEST_OS_LINUX) || defined(SIGAR_TEST_OS_DARWIN))
            assert(IS_IMPL_U64(diskusage.time));
#endif
#if !defined(SIGAR_TEST_OS_DARWIN)
            assert(IS_IMPL_U64(diskusage.snaptime));
#endif
#if 0
            /* is -1 if undefined */
            assert(diskusage.service_time >= 0);
            assert(diskusage.queue >= 0);
#endif
            if (given_path[0]) {
                if (strstr(given_path, fs.dir_name)) {
                    size_t len = strlen(fs.dir_name);
                    if (len > best_match) {
                        best_match = len;
                        dsu = diskusage;
                    }
                }
            } else {
                fprintf(stdout, "Read=" SIGAR_F_U64 ", Write=" SIGAR_F_U64
                        ", Queue=" SIGAR_F_U64 ", Time=" SIGAR_F_U64
                        ", SnapTime=" SIGAR_F_U64
                        ", Service Time=%g, QueueDepth=%g\n",
                        diskusage.rtime, diskusage.wtime, diskusage.qtime,
                        diskusage.time,
                        diskusage.snaptime, diskusage.service_time,
                        diskusage.queue);
            }
        } else {
            switch (ret) {
            case ESRCH: /* macosx */
            case ENXIO: /* solaris */
            case ENOENT: /* aix */
            case SIGAR_ENOTIMPL: /* hpux */
                /* track the expected error code */
                fprintf(stderr, "sigar_disk_usage_get(%s) ret = %d (%s)\n",
                        fs.dev_name,
                        ret, sigar_strerror(t, ret));
                break;
            default:
                fprintf(stderr, "sigar_disk_usage_get(%s) ret = %d (%s)\n",
                        fs.dev_name,
                        ret, sigar_strerror(t, ret));
                assert(ret == SIGAR_OK);
                break;
            }
        }
    }

    if (best_match) {
        fprintf(stdout, "Read=" SIGAR_F_U64 ", Write=" SIGAR_F_U64
                ", Queue=" SIGAR_F_U64 ", Time=" SIGAR_F_U64
                ", SnapTime=" SIGAR_F_U64
                ", Service Time=%g, QueueDepth=%g\n",
                dsu.rtime, dsu.wtime, dsu.qtime,
                dsu.time, dsu.snaptime, dsu.service_time,
                dsu.queue);
    }

    sigar_file_system_list_destroy(t, &fslist);

    return 0;
}

int main(int argc, char **argv) {
    sigar_t *t;
    int err = 0;

    assert(SIGAR_OK == sigar_open(&t));

    if (argc > 1) {
        given_path = argv[1];
    }

    test_sigar_disk_stats(t);

    sigar_close(t);

    return err ? -1 : 0;
}
