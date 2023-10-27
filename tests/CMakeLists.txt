cb_add_test_executable(sigar_tests_child sigar_tests_child.cc)
target_link_libraries(sigar_tests_child platform)
add_sanitizers(sigar_tests_child)

cb_add_test_executable(sigar_tests
                       sigar_tests.cc
)
target_link_libraries(sigar_tests
                      sigar
                      platform
                      Folly::folly
                      GTest::gtest
                      GTest::gtest_main)
add_sanitizers(sigar_tests)
add_dependencies(sigar_tests sigar_tests_child)
target_compile_definitions(sigar_tests PRIVATE SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")
add_test(NAME sigar-unit-tests
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        COMMAND sigar_tests)

cb_add_test_executable(sigar_cpp_tests
        sigar_cpp_tests.cc
        sigar_port_tests.cc
        $<TARGET_OBJECTS:sigar_port_impl>)
target_link_libraries(sigar_cpp_tests
        sigar_cpp
        platform
        Folly::folly
        GTest::gtest
        GTest::gtest_main)
add_sanitizers(sigar_cpp_tests)
target_compile_definitions(sigar_cpp_tests PRIVATE SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")
add_test(NAME sigar-cpp-unit-tests
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        COMMAND sigar_cpp_tests)
