add_library(sigar_port_impl OBJECT sigar_port.c sigar_port_util.cc)
target_link_libraries(sigar_port_impl PRIVATE sigar)
target_link_libraries(sigar_port_impl PUBLIC fmt::fmt)

add_executable(sigar_port $<TARGET_OBJECTS:sigar_port_impl> sigar_port_main.cc)

# Use mcd_time from kv_engine to format a timestamp in the logs
# We could have used the logger form memcached as it deals with
# file rotation, but that would require additional changes
# in ns_server to make sure we only keep N files.
target_include_directories(sigar_port
        SYSTEM PRIVATE ${Memcached_SOURCE_DIR}/include)
target_link_libraries(sigar_port PRIVATE sigar mcd_time fmt::fmt platform)

install(TARGETS sigar_port RUNTIME DESTINATION bin)
