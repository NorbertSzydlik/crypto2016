cmake_minimum_required(VERSION 2.6)
project(Lista2)
SET (CMAKE_C_COMPILER             "/usr/bin/clang")
SET (CMAKE_CXX_COMPILER             "/usr/bin/clang++")
set (CMAKE_CXX_STANDARD 14)

add_executable(lista2 main.cpp)
target_link_libraries(lista2 ssl crypto pthread)

