cmake_minimum_required(VERSION 3.4)
project(${TEST_PROJECT})

set(SRC main.cpp kw.cpp kuw.cpp sha256.cpp stribog.cpp)
add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} gtest crypto pthread)
file(COPY kwdata DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY gost3411data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY sha256data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

