# ideally we should have linked sigar_cpp with cgroup as it use that
# but the cgroup functionality is also linked into platform (as
# it utilize methods in there) and we'll get the symbols
# defined twice (both in cgroup and in platform). The ones
# in cgroup is to be used _without_ overriding operator new
# etc as the shared object is used from go programs where
# we don't want to override operator new...
#
# Instead this means that programs linking with sigar_cpp needs
# to add which underlying cgroup library they want...
add_library(sigar_cpp OBJECT os/sigar_iface.cc
        os/darwin/darwin_sigar.cc
        os/win32/win32_sigar.cc
        os/linux/linux_sigar.cc)
target_link_libraries(sigar_cpp PRIVATE platform_headers)
target_link_libraries(sigar_cpp PUBLIC nlohmann_json::nlohmann_json)

if (APPLE)
    target_link_libraries(sigar_cpp PRIVATE proc)
elseif (WIN32)
    target_compile_definitions(sigar_cpp PRIVATE -D_CRT_NONSTDC_NO_DEPRECATE)
    target_link_libraries(sigar_cpp
            PRIVATE platform ws2_32 netapi32 version kernel32 ntdll psapi)
endif ()

set_target_properties(sigar_cpp
        PROPERTIES
        POSITION_INDEPENDENT_CODE
        true)
target_include_directories(sigar_cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(sigar_cpp PUBLIC ${sigar_SOURCE_DIR}/include)

add_library(sigar SHARED
        sigar.cc
        sigar_control_group.cc
        sigar_format.cc
        sigar_private.h)
target_link_libraries(sigar PRIVATE sigar_cpp)
target_compile_definitions(sigar PRIVATE -DBUILDING_SIGAR=1)
target_include_directories(sigar PUBLIC ${sigar_SOURCE_DIR}/include)
if (UNIX)
    target_link_libraries(sigar PRIVATE cgroup)
endif ()

INSTALL(TARGETS sigar
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        )
