add_library(sigar_port_impl OBJECT sigar_port.cc)
target_link_libraries(sigar_port_impl PRIVATE sigar nlohmann_json::nlohmann_json platform)

add_executable(sigar_port $<TARGET_OBJECTS:sigar_port_impl> sigar_port_main.cc)
target_link_libraries(sigar_port PRIVATE sigar nlohmann_json::nlohmann_json)
if (UNIX)
    target_link_libraries(sigar_port PRIVATE cgroup)
endif()

install(TARGETS sigar_port RUNTIME DESTINATION bin)
