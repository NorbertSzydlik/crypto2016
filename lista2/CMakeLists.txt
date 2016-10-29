cmake_minimum_required(VERSION 2.6)
project(Lista2)
SET (CMAKE_C_COMPILER             "/usr/bin/clang")
SET (CMAKE_CXX_COMPILER             "/usr/bin/clang++")
set (CMAKE_CXX_STANDARD 14)

add_executable(lista2_1 main_1.cpp)
target_link_libraries(lista2_1 ssl crypto pthread)

add_executable(lista2_2 main_2.cpp)
target_link_libraries(lista2_2 ssl crypto pthread)

add_executable(lista2_test main_test.cpp)
target_link_libraries(lista2_test ssl crypto pthread)
