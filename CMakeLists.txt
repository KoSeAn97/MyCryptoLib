cmake_minimum_required(VERSION 3.4.1)
project(crypttest CXX)

add_definitions(-Wall -std=c++11)

# ----------- Google Test ------------------
set(GTEST_ROOT gtest-1.8.0)
set(BUILD_GTEST ON CACHE BOOL "Builds the gooletest subproject")
set(BUILD_GMOCK OFF CACHE BOOL "Builds the googlemock subproject")
add_subdirectory(${GTEST_ROOT} gtest)
include_directories(${GTEST_ROOT}/googletest/include)

# ------------ MyCryptoLib -----------------
include_directories(include)
add_subdirectory(MyCryptoLib MyCryptoLib)
add_subdirectory(app cryptutil)

# ------------- Tests ----------------------
set(TEST_PROJECT test_${PROJECT_NAME})
add_test(NAME ${TEST_PROJECT} COMMAND ${TEST_PROJECT})
add_subdirectory(tests)

enable_testing()