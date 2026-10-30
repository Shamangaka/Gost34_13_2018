cmake_minimum_required(VERSION 3.20)
project(gost_project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

###############################################################################
## library and test-vector generator ##########################################
###############################################################################

add_library(qalqan STATIC
  src/main/Qalqan.cpp
  src/main/Modes.cpp
  src/main/PRNG.cpp
  src/main/TestVectors.cpp
)
target_include_directories(qalqan PUBLIC src/main)
target_compile_options(qalqan PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/W4>
  $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra>
)

# gost_test writes the Appendix A vectors for resources/input.bin to
# resources/output.txt (run it from the build directory).
add_executable(gost_test src/main/Gost.cpp)
target_link_libraries(gost_test PRIVATE qalqan)
file(COPY resources DESTINATION ${CMAKE_BINARY_DIR})

###############################################################################
## testing ####################################################################
###############################################################################

enable_testing()
find_package(GTest)
if(GTest_FOUND)
  file(GLOB test_sources src/test/*.cpp)
  add_executable(unit_tests ${test_sources})
  target_link_libraries(unit_tests PRIVATE qalqan GTest::gtest_main)
  target_compile_definitions(unit_tests PRIVATE QALQAN_RESOURCES="${CMAKE_SOURCE_DIR}/resources")
  include(GoogleTest)
  gtest_discover_tests(unit_tests)
else()
  message(STATUS "GTest not found: unit_tests target disabled")
endif()

###############################################################################
## packaging ##################################################################
###############################################################################

install(TARGETS gost_test DESTINATION example_destination)
install(DIRECTORY resources DESTINATION example_destination)

set(CPACK_PACKAGE_NAME "gost_test")
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_MONOLITHIC_INSTALL 1)
include(CPack)
