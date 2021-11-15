ADD_DEFINITIONS(-U NDEBUG)
MACRO(SIGAR_TEST name)
	cb_add_test_executable(${name} ${name}.c)
	TARGET_LINK_LIBRARIES(${name}  sigar)
	ADD_TEST(${name} ${name})
ENDMACRO(SIGAR_TEST name)

INCLUDE_DIRECTORIES(../include/)

## linux
IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  ADD_DEFINITIONS(-DSIGAR_TEST_OS_LINUX)
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux")

## macosx
IF(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  ADD_DEFINITIONS(-DSIGAR_TEST_OS_DARWIN)
ENDIF()

IF(WIN32)
  ADD_DEFINITIONS(-DSIGAR_TEST_OS_WIN32)
ENDIF(WIN32)

SIGAR_TEST(t_sigar_cpu)
SIGAR_TEST(t_sigar_mem)
SIGAR_TEST(t_sigar_netconn)
SIGAR_TEST(t_sigar_pid)
SIGAR_TEST(t_sigar_proc)
SIGAR_TEST(t_sigar_swap)

if (NOT WIN32)
    add_executable(t_pchilds t_pchilds.cc)
    target_include_directories(t_pchilds INTERFACE PRIVATE ${Platform_SOURCE_DIR/include})
    target_link_libraries(t_pchilds platform sigar)
    add_test(t_sigar_pchilds t_pchilds)
endif (NOT WIN32)
