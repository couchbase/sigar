/*
 *    Copyright 2022-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include "sigar/logger.h"
#include "sigar_port.h"

#ifdef WIN32
#include <fcntl.h>
#include <io.h>
#include <process.h>
#else
#include <unistd.h>
#endif

#include <getopt.h>
#include <nlohmann/json.hpp>
#include <platform/dirutils.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <charconv>
#include <iostream>
#include <optional>
#include <string>

using namespace std::string_view_literals;

// arg spdlog::level::from_str didn't like these strings..
static spdlog::level::level_enum to_level(std::string_view view) {
    if (view == "trace"sv) {
        return spdlog::level::trace;
    }
    if (view == "debug"sv) {
        return spdlog::level::debug;
    }
    if (view == "info"sv) {
        return spdlog::level::info;
    }
    if (view == "warning"sv) {
        return spdlog::level::warn;
    }
    if (view == "error"sv) {
        return spdlog::level::err;
    }
    if (view == "critical"sv) {
        return spdlog::level::critical;
    }

    throw std::runtime_error(fmt::format("Unknown log level: \"{}\""));
}

static std::shared_ptr<spdlog::logger> logger;

static sigar_pid_t parse_pid(std::string_view pidstr) {
    try {
        sigar_pid_t value{};
        const auto [ptr, ec]{std::from_chars(
                pidstr.data(), pidstr.data() + pidstr.size(), value)};
        if (ec != std::errc()) {
            if (ec == std::errc::invalid_argument) {
                throw std::invalid_argument("no conversion");
            }
            if (ec == std::errc::result_out_of_range) {
                throw std::out_of_range("value exceeds long");
            }
            throw std::system_error(std::make_error_code(ec));
        }
        if (ptr != pidstr.data() + pidstr.size()) {
            throw std::invalid_argument("invalid characters in pid string");
        }
        return value;
    } catch (const std::exception& exception) {
        std::cerr << "Failed to parse pid: " << exception.what() << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

static void logit(int level, std::string_view msg) {
    logger->log(spdlog::level::level_enum(level), "{}", msg);
    logger->flush();
}

int main(int argc, char** argv) {
    using namespace sigar_port;

#ifdef WIN32
    _setmode(1, _O_BINARY);
    _setmode(0, _O_BINARY);
#endif

    bool snapshot = false;
    std::optional<sigar_pid_t> babysitter_pid;
    std::optional<std::string> logfile;
    std::optional<std::string> configfile;
    spdlog::level::level_enum loglevel = spdlog::level::err;

    enum Option {
        BabysitterPid,
        LogFile,
        ConfigFile,
        LogLevel,
        Snapshot,
        HumanReadable,
        Json,
        Help
    };

    std::vector<option> long_options = {
            {"babysitter_pid",
             required_argument,
             nullptr,
             Option::BabysitterPid},
            {"logfile", required_argument, nullptr, Option::LogFile},
            {"config", required_argument, nullptr, Option::ConfigFile},
            {"loglevel", required_argument, nullptr, Option::LogLevel},
            {"snapshot", no_argument, nullptr, Option::Snapshot},
            {"human-readable", no_argument, nullptr, Option::HumanReadable},
            {"json", no_argument, nullptr, Option::Json},
            {"help", no_argument, nullptr, Option::Help},
            {nullptr, 0, nullptr, 0}};
    int cmd;
    while ((cmd = getopt_long(argc, argv, "", long_options.data(), nullptr)) !=
           EOF) {
        switch (cmd) {
        case Option::BabysitterPid:
            if (optarg == "self"sv) {
                babysitter_pid = getpid();
            } else {
                babysitter_pid = parse_pid(optarg);
            }
            break;
        case Option::LogFile:
            logfile = optarg;
            break;
        case Option::ConfigFile:
            configfile = optarg;
            break;
        case Option::LogLevel:
            try {
                loglevel = to_level(optarg);
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << std::endl;
                std::exit(SIGAR_INVALID_USAGE);
            }
            break;
        case Option::Snapshot:
            snapshot = true;
            break;
        case Option::HumanReadable:
            human_readable_output = true;
            break;
        case Option::Json:
            // Not used
            break;
        case Option::Help:
        default:
            std::cerr << R"(sigar_port [options]
--babysitter_pid pid  The parent pid of all processes to report
--logfile filename    Use filename for logging
--config filename     Read extra config from file
--loglevel level      Use the provided log level
--snapshot            Dump the current information and terminate
--human-readable      Print sizes in "human readable" form by converting to
                      (K/M/T/P) by using power 1024. Print times as
                      1h:1m:32s (or just "22 ms")
--help                Print this help
)";
            std::exit(SIGAR_INVALID_USAGE);
        }
    }

#ifdef WIN32
    indentation = human_readable_output ? 2 : -1;
#else
    indentation = (isatty(fileno(stdout)) || isatty(fileno(stdin)) ||
                   human_readable_output)
                          ? 2
                          : -1;
#endif

    if (logfile) {
        // Create a file rotating logger with 1mb size max and 3 rotated files
        auto max_size = 1024 * 1024;
        auto max_files = 3;
        logger = spdlog::rotating_logger_mt(
                "sigar_logger", *logfile, max_size, max_files);
    } else {
        if (indentation != -1) {
            logger = std::make_shared<spdlog::logger>(
                    "sigar_logger",
                    std::make_shared<spdlog::sinks::stderr_color_sink_st>());
        }
        if (!logger) {
            logger = std::make_shared<spdlog::logger>(
                    "sigar_logger",
                    std::make_shared<spdlog::sinks::null_sink_mt>());
        }
        spdlog::register_logger(logger);
    }

    logger->set_level(loglevel);
    logger->set_pattern("%^%Y-%m-%dT%T.%f%z %l %v%$");

    if (configfile) {
        if (cb::io::isFile(*configfile)) {
            try {
                const auto json =
                        nlohmann::json::parse(cb::io::loadFile(*configfile));

                logger->set_level(to_level(json.value("loglevel", "error")));
            } catch (const std::exception& exception) {
                logger->error("Failed to read configuration: {}",
                              exception.what());
            }
        } else {
            logger->info(R"(Configuration file "{}" not found)", *configfile);
        }
    }

    sigar::set_log_callback(loglevel, logit);

    input = stdin;
    output = stdout;

    int ret;
    try {
        if (snapshot) {
            if (babysitter_pid) {
                logger->info("Request snapshot with babysitter pid {}",
                             *babysitter_pid);
            } else {
                logger->info("Request snapshot");
            }
            ret = sigar_port_snapshot(babysitter_pid);
        } else {
            if (babysitter_pid) {
                logger->info("Starting sigar_port monitoring babysitter pid {}",
                             babysitter_pid.value());
            } else {
                logger->info("Starting sigar_port");
            }
            ret = sigar_port_main(babysitter_pid);
        }
    } catch (const std::exception& exception) {
        logger->error("Exception occurred: {}", exception.what());
        ret = SIGAR_EXCEPTION;
    } catch (...) {
        logger->error("Unknown exception occurred");
        ret = SIGAR_OTHER_EXCEPTION;
    }

    logger->info("Terminate with exit code: {}", ret);
    logger->flush();
    logger.reset();
    return ret;
}
