/*
 *     Copyright 2023-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#pragma once

#include <sigar/types.h>

#include <array>
#include <memory>
#include <tuple>
#include <unordered_map>

namespace sigar {

/**
 * The Linux support utilize the /proc filesystem to fetch the information
 * and may be built (and tested) on other platforms. Given that a lot of
 * the developers use a MacOS laptop it make development easier by building
 * the linux version on MacOS and run the unit tests (without having to
 * upload a patch to gerrit to get CV to build on linux and spot all typos)
 */
enum class Backend {
    /// The correct backend to use on the running platform
    Native,
    /// The backend used on MacOSX
    Apple,
    /// The backend used on Linux (based on /proc)
    Linux,
    /// The backend used on Windows
    Windows
};

/**
 * The C++ interface to sigar
 */
struct SigarIface {
public:
    /**
     * Create a new instance of the SigarInterface
     *
     * @param backed The backend to use (only unit tests should request
     *               something else than Native)
     * @return A newly created instance
     * @throws a subclass of std::exception if an error occurs
     */
    static std::unique_ptr<SigarIface> New(Backend backed = Backend::Native);

#if defined(__linux__) || defined(__APPLE__)
    /**
     * Set the directory to be considered as the root of the filesystem.
     * By default this is set to "/", but in order to allow for unit testing
     * by using a mock /proc filesystem it may be overridden.
     *
     * This method should _only_ be used for unit testing
     */
    static void set_mock_root(const char* root);
#endif

    virtual ~SigarIface() = default;

    /**
     * Get the system memory information. This method is to be replaced
     * by get_system_information which returns memory, swap and cpu
     *
     * @throws a subclass of std::exception if an error occurs
     */
    virtual sigar_mem_t get_memory() = 0;

    /**
     * Get the system swap information. This method is to be replaced
     * by get_system_information which returns memory, swap and cpu
     *
     * @throws a subclass of std::exception if an error occurs
     */
    virtual sigar_swap_t get_swap() = 0;

    /**
     * Get the system CPU information. This method is to be replaced
     * by get_system_information which returns memory, swap and cpu
     *
     * @throws a subclass of std::exception if an error occurs
     */
    virtual sigar_cpu_t get_cpu() = 0;

    /**
     * Get the memory information for the provided process.
     * This method is to be replaced by get_process_information
     * which returns memory and cpu information for the process
     *
     * @param pid the process to query
     * @throws a subclass of std::exception if an error occurs
     */
    virtual sigar_proc_mem_t get_proc_memory(sigar_pid_t pid) = 0;

    /**
     * Get the process state information for the provided process.
     *
     * @param pid the process to query
     * @throws a subclass of std::exception if an error occurs
     */
    virtual sigar_proc_state_t get_proc_state(sigar_pid_t pid) = 0;

    /**
     * Iterate over all child processes for the provided pid and
     * call the callback with the child information
     *
     * @param pid the process to locate the children for
     * @param callback the callback to call for each process
     * @throws a subclass of std::exception if an error occurs
     */
    virtual void iterate_child_processes(
            sigar_pid_t pid, IterateChildProcessCallback callback) = 0;

    /**
     * Iterate over all the threads in the current call the callback with
     * the thread information
     *
     * @param callback the callback to call for each thread
     * @throws a subclass of std::exception if an error occurs
     */
    virtual void iterate_threads(IterateThreadCallback callback) = 0;

    /**
     * Iterate over all the disks on the current system and call the callback
     * with the disk information
     *
     * @param callback the callback to call for each disk
     * @throws a subclass of std::exception if an error occurs
     */
    virtual void iterate_disks(IterateDiskCallback callback) = 0;

    /**
     * Get the cgroup information
     * @throws a subclass of std::exception if an error occurs
     */
    virtual sigar_control_group_info get_control_group_info() const = 0;

    /**
     * Get the cpu information for the provided process.
     * This method is to be replaced by get_process_information
     * which returns memory and cpu information for the process
     *
     * @param pid the process to query
     * @throws a subclass of std::exception if an error occurs
     */
    sigar_proc_cpu_t get_proc_cpu(sigar_pid_t pid);

protected:
    SigarIface();

    /// A process cache used by get_proc_cpu
    std::unordered_map<sigar_pid_t, sigar_proc_cpu_t> process_cache;

    /**
     * Get the process times for the provided pid
     *
     * @param pid the process to query
     * @return tuple of start_time, user, sys, total;
     */
    virtual std::tuple<uint64_t, uint64_t, uint64_t, uint64_t> get_proc_time(
            sigar_pid_t pid) = 0;
};

} // namespace sigar
