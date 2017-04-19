cmake_minimum_required(VERSION 3.4.1)
project(MyCryptoLib CXX)

add_definitions(-Wall -std=c++11 -Wno-constant-logical-operand)

# ------------- Variables ------------------
file(GLOB crypto_SRC "src/*.cpp" "src/*.c")

# ------------ MyCryptoLib -----------------
include_directories(include)
add_library(crypto STATIC ${crypto_SRC})