## sigar has some base files + a set of platform specific files

INCLUDE_DIRECTORIES(../include/)

## linux
IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  SET(SIGAR_SRC os/linux/linux_sigar.c)
  INCLUDE_DIRECTORIES(os/linux/)
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux")

## macosx
IF (APPLE)
    SET(SIGAR_SRC os/darwin/darwin_sigar.c)
    INCLUDE_DIRECTORIES(os/darwin/)
    INCLUDE_DIRECTORIES(/Developer/Headers/FlatCarbon/)
    ADD_DEFINITIONS(-DDARWIN)
    ADD_DEFINITIONS(-DDARWIN_HAS_LIBPROC_H=1)
    SET(SIGAR_LINK_FLAGS "-framework CoreServices -framework IOKit")
ENDIF (APPLE)

IF(WIN32)
  ADD_DEFINITIONS(-DSIGAR_SHARED)
  ADD_DEFINITIONS(-D_CRT_NONSTDC_NO_DEPRECATE)
  SET(SIGAR_SRC os/win32/peb.c os/win32/win32_sigar.c os/win32/wmi.cpp os/win32/win32_util.cc)
  INCLUDE_DIRECTORIES(os/win32)
ENDIF(WIN32)

SET(SIGAR_SRC ${SIGAR_SRC}
  sigar.c
  sigar_cache.c
  sigar_fileinfo.c
  sigar_format.c
  sigar_util.c
)

ADD_LIBRARY(sigar SHARED ${SIGAR_SRC})
SET_TARGET_PROPERTIES(sigar PROPERTIES COMPILE_FLAGS -DBUILDING_SIGAR=1)

IF(WIN32)
	TARGET_LINK_LIBRARIES(sigar ws2_32 netapi32 version)
ENDIF(WIN32)
IF(SIGAR_LINK_FLAGS)
  SET_TARGET_PROPERTIES(sigar PROPERTIES LINK_FLAGS "${SIGAR_LINK_FLAGS}")
ENDIF(SIGAR_LINK_FLAGS)

INSTALL(TARGETS sigar
	RUNTIME DESTINATION bin
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
	)
