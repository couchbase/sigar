/*
 *    Copyright 2022-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include "sigar.h"
#include "sigar_port.h"

#ifdef WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include <fmt/format.h>
#include <fmt/ostream.h>
#include <getopt.h>
#include <memcached/isotime.h>
#include <nlohmann/json.hpp>
#include <platform/dirutils.h>
#include <sys/stat.h>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <iostream>
#include <optional>

static int parse_pid(char* pidstr, std::optional<sigar_pid_t>& result) {
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
    result = (sigar_pid_t)pid;
    return 1;
}

/// The name of the log file to use
static std::string logfile;

/// Get the size of the logfile. Assume it is empty if we fail to get the
/// file size (the file doesn't exists for instance)
static std::size_t get_logfile_size() {
    struct stat st;
    if (stat(logfile.c_str(), &st) == 0) {
        return std::size_t(st.st_size);
    }
    return 0;
}

namespace sigar {
std::string to_string(const LogLevel& level) {
    switch (level) {
    case LogLevel::Debug:
        return "DEBUG";
    case LogLevel::Info:
        return "INFO";
    case LogLevel::Error:
        return "ERROR";
    }

    return std::to_string(int(level));
}

std::ostream& operator<<(std::ostream& os, const LogLevel& level) {
    os << to_string(level);
    return os;
}
} // namespace sigar

/**
 * The callback function which implements all of the logging:
 *   * Check if the message fits within the 20MB limit of the current file
 *   * If it doesn't fit; rename the current file to .old
 *   * Write the message into the file.
 *
 * @param level The log level for the message
 * @param msg The message to log
 */
void logit(sigar::LogLevel level, std::string_view msg) {
    static const std::size_t MaxLogSize = 20 * 1024 * 1024;
    static FILE* fp = nullptr;
    static std::size_t nbytes = 0;

    if (!fp) {
        // the logfile is not open, get the size of the file so that we know
        // when to rotate
        nbytes = get_logfile_size();
    }

    const auto message = fmt::format(
            "{} {}: {}\n", ISOTime::generatetimestamp(), level, msg);

    // Check to see if the message still fits in the current file
    if ((nbytes + message.size()) > MaxLogSize) {
        if (fp) {
            fclose(fp);
            fp = nullptr;
        }

        // Try to rename the file, but a failure is not fatal as we'll
        // just try again at a later time
        std::string old = logfile + ".old";
        ::remove(old.c_str());
        ::rename(logfile.c_str(), old.c_str());
    }

    if (!fp) {
        // The logfile isn't open (may have been closed due to rotation)
        nbytes = get_logfile_size();
        fp = fopen(logfile.c_str(), "a");
        if (!fp) {
            return;
        }
    }

    fwrite(message.data(), message.size(), 1, fp);
    fflush(fp);
    nbytes += message.size();
}

int main(int argc, char** argv) {
#ifdef WIN32
    _setmode(1, _O_BINARY);
    _setmode(0, _O_BINARY);
#endif

    std::optional<sigar_pid_t> babysitter_pid;
    enum Option { BabysitterPid, Logfile, Config, Help };

    std::string config;
    auto loglevel = sigar::LogLevel::Error;

    const std::vector<option> options{
            {{"babysitter_pid",
              required_argument,
              nullptr,
              Option::BabysitterPid},
             {"logfile", required_argument, nullptr, Option::Logfile},
             {"config", required_argument, nullptr, Option::Config},
             {"help", no_argument, nullptr, Option::Help},
             {nullptr, 0, nullptr, 0}}};

    int cmd;
    while ((cmd = getopt_long(argc, argv, "", options.data(), nullptr)) !=
           EOF) {
        switch (cmd) {
        case Option::BabysitterPid:
            if (!parse_pid(optarg, babysitter_pid)) {
                fprintf(stderr, "Failed to parse pid\n");
                exit(SIGAR_INVALID_USAGE);
            }
            break;
        case Option::Logfile:
            logfile.assign(optarg);
            sigar::set_log_callback(loglevel, logit);
            break;
        case Option::Config:
            config = optarg;
            break;
        case Option::Help:
        default:
            std::cerr << "Usage: " << argv[0] << R"( [options]

Options:
   --config=filename        Read extra config from config file
   --logfile=filename       Use filename for logging
   --babysitter_pid=<pid>   The parent pid of all processes to report

)";
            exit(EXIT_FAILURE);
        }
    }

    if (!babysitter_pid) {
        std::cerr << "No pid provided" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (!config.empty()) {
        if (cb::io::isFile(config)) {
            try {
                const auto json =
                        nlohmann::json::parse(cb::io::loadFile(config));
                logfile = json.value("logfile", logfile);
                const auto lvl = json.value("loglevel", std::string{"error"});
                if (lvl == "debug") {
                    loglevel = sigar::LogLevel::Debug;
                } else if (lvl == "info") {
                    loglevel = sigar::LogLevel::Info;
                }
            } catch (const std::exception& exception) {
                sigar::logit(
                        sigar::LogLevel::Error,
                        fmt::format("Failed to read config file \"{}\": {}",
                                    config,
                                    exception.what()));
            }
        }
    }

    if (!logfile.empty()) {
        sigar::set_log_callback(loglevel, logit);
    }

    int ret;
    try {
        sigar::logit(
                sigar::LogLevel::Info,
                fmt::format("Starting sigar_port monitoring babysitter pid {}",
                            babysitter_pid.value()));
        ret = sigar_port_main(babysitter_pid.value(), stdin, stdout);
    } catch (const std::exception& exception) {
        sigar::logit(sigar::LogLevel::Error,
                     fmt::format("Exception occurred: {}", exception.what()));
        ret = SIGAR_EXCEPTION;
    } catch (...) {
        sigar::logit(sigar::LogLevel::Error, "Unknown exception thrown");
        ret = SIGAR_OTHER_EXCEPTION;
    }

    sigar::logit(sigar::LogLevel::Info,
                 fmt::format("Terminate with exit code: {}", ret));
    return ret;
}
