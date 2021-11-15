## sigar has some base files + a set of platform specific files

INCLUDE_DIRECTORIES(../include/)

SET(SIGAR_COMMON_SRC
    sigar.c
    sigar_cache.c
    sigar_fileinfo.c
    sigar_format.c
    sigar_util.c
    )

## linux
IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(sigar SHARED ${SIGAR_COMMON_SRC} os/linux/linux_sigar.c)
    target_include_directories(sigar PRIVATE os/linux)
ENDIF (CMAKE_SYSTEM_NAME STREQUAL "Linux")

## macosx
IF (APPLE)
    add_library(sigar SHARED ${SIGAR_COMMON_SRC} os/darwin/darwin_sigar.c)
    target_include_directories(sigar PRIVATE os/darwin/)
    target_include_directories(sigar SYSTEM PRIVATE /Developer/Headers/FlatCarbon/)
    target_compile_definitions(sigar PRIVATE -DDARWIN -DDARWIN_HAS_LIBPROC_H=1)
    target_link_libraries(sigar PRIVATE "-framework CoreServices -framework IOKit")
ENDIF (APPLE)

IF (WIN32)
    add_library(sigar SHARED ${SIGAR_COMMON_SRC}
                os/win32/peb.c
                os/win32/win32_sigar.c
                os/win32/wmi.cpp
                os/win32/win32_util.cc)
    target_compile_definitions(sigar PRIVATE -DSIGAR_SHARED -D_CRT_NONSTDC_NO_DEPRECATE)
    target_include_directories(sigar PRIVATE os/win32)
    target_link_libraries(sigar ws2_32 netapi32 version)
ENDIF (WIN32)

target_compile_definitions(sigar PRIVATE -DBUILDING_SIGAR=1)

INSTALL(TARGETS sigar
	RUNTIME DESTINATION bin
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
	)
