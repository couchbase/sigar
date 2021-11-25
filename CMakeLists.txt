PROJECT(sigar C CXX)

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckTypeSize)
INCLUDE(CTest)
INCLUDE(InstallRequiredSystemLibraries)

ENABLE_TESTING()

# The unit test tries to load the shared object, and this
# fails on windows as we don't add a "runtime path" for the
# linker to find sigar.dll. The easiest workaround is
# to put them in the same directory and it should work out
# of the box. The other components which currently link
# with sigar tries to look for the library in the src directory
# so the easiest fix is to ensure that the other binaries
# also end up there
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/src)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/src)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/src)

IF(WIN32)
	## make sure we only use the smallest set of
	## headers on win32. Otherwise we get clashes
	## between winsock2.h and winsock.h
	ADD_DEFINITIONS(-DWIN32_LEAN_AND_MEAN)

	# force the correct version for the redist manifest
	ADD_DEFINITIONS(-D_BIND_TO_CURRENT_MFC_VERSION=1 -D_BIND_TO_CURRENT_CRT_VERSION=1)
	# turn off security warnings for system calls
	ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
ENDIF(WIN32)

IF ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
   # CLang emits a warning for all asm blocks
   SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-language-extension-token")
ENDIF ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(tests)
ADD_SUBDIRECTORY(programs)
