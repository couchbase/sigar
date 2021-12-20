INCLUDE_DIRECTORIES(BEFORE ${PROJECT_SOURCE_DIR}/include/)

ADD_EXECUTABLE(sigar_port sigar_port.c sigar_port_util.cc)
TARGET_LINK_LIBRARIES(sigar_port sigar)

INSTALL(TARGETS sigar_port RUNTIME DESTINATION bin)
