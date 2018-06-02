cmake_minimum_required(VERSION 3.4.1)
project(cryptutil CXX)

add_definitions(-Wall -std=c++11)

file(GLOB app_src "src/*.cpp" "src/*.c")
add_executable(cryptutil ${app_src})
target_link_libraries(cryptutil crypto)