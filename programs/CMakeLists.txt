add_library(sigar_port_impl OBJECT sigar_port.c sigar_port_util.cc)
target_link_libraries(sigar_port_impl PRIVATE sigar)

add_executable(sigar_port $<TARGET_OBJECTS:sigar_port_impl> sigar_port_main.cc)
target_link_libraries(sigar_port sigar)

install(TARGETS sigar_port RUNTIME DESTINATION bin)
