add_library(sigar_port_impl OBJECT sigar_port.cc)
target_link_libraries(sigar_port_impl
        PRIVATE sigar_cpp nlohmann_json::nlohmann_json platform)

add_executable(sigar_port $<TARGET_OBJECTS:sigar_port_impl> sigar_port_main.cc)
target_link_libraries(sigar_port
        PRIVATE sigar_cpp platform nlohmann_json::nlohmann_json)

cb_add_test_executable(sigar_interactive_test_cpp sigar_interactive_test.cc)

install(TARGETS sigar_port RUNTIME DESTINATION bin)
