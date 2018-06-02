cmake_minimum_required(VERSION 3.4.1)
project(MyCryptoLib CXX)

add_definitions(-Wall -std=c++11 -Wno-constant-logical-operand -O3)

file(GLOB crypto_src "src/*.cpp" "src/*.c")
file(GLOB crypto_inc "../include/MyCryptoLib/*.h" "../include/MyCryptoLib/*.hpp")
add_library(crypto STATIC ${crypto_src} ${crypto_inc})
