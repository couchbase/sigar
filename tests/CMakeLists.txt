cb_add_test_executable(sigar_tests sigar_tests.cc)
target_link_libraries(sigar_tests
                      sigar
                      platform
                      Folly::folly
                      GTest::gtest
                      GTest::gtest_main)
add_test(NAME sigar-unit-tests
         WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
         COMMAND sigar_tests)
