## sigar has some base files + a set of platform specific files

SET(SIGAR_COMMON_SRC
    sigar.cc
    sigar_format.cc
    sigar_private.h
    )

## linux
IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(sigar SHARED ${SIGAR_COMMON_SRC}
                os/linux/linux_sigar.cc
                os/linux/sigar_cgroup.cc)
    target_include_directories(sigar SYSTEM PRIVATE AFTER
                               ${BOOST_INCLUDE_DIR}
                               ${Platform_SOURCE_DIR}/include)
    target_link_libraries(sigar PRIVATE cgroup)
ENDIF (CMAKE_SYSTEM_NAME STREQUAL "Linux")

## macosx
IF (APPLE)
    add_library(sigar SHARED ${SIGAR_COMMON_SRC}
                os/darwin/darwin_sigar.cc
                sigar_control_group_not_supported.cc)
    target_link_libraries(sigar PRIVATE proc)
ENDIF (APPLE)

IF (WIN32)
    add_library(sigar SHARED ${SIGAR_COMMON_SRC}
                os/win32/win32_sigar.cc
                sigar_control_group_not_supported.cc)
    target_compile_definitions(sigar PRIVATE -D_CRT_NONSTDC_NO_DEPRECATE)
    target_link_libraries(sigar platform ws2_32 netapi32 version kernel32 ntdll psapi)
ENDIF (WIN32)

target_compile_definitions(sigar PRIVATE -DBUILDING_SIGAR=1)
target_include_directories(sigar PUBLIC ${sigar_SOURCE_DIR}/include)
target_include_directories(sigar PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

INSTALL(TARGETS sigar
	RUNTIME DESTINATION bin
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
	)
