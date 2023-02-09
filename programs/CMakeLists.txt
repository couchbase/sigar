add_library(sigar_port_impl OBJECT sigar_port.cc)
target_link_libraries(sigar_port_impl PRIVATE sigar nlohmann_json::nlohmann_json)

add_executable(sigar_port $<TARGET_OBJECTS:sigar_port_impl> sigar_port_main.cc)
target_link_libraries(sigar_port sigar nlohmann_json::nlohmann_json)

install(TARGETS sigar_port RUNTIME DESTINATION bin)
