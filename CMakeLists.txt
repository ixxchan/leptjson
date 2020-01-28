cmake_minimum_required(VERSION 2.6)
project(leptjson C)

set(CMAKE_C_STANDARD 99)

if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ansi -pedantic -Wall")
endif ()

add_library(leptjson leptjson.c)
add_executable(leptjson_test test.c)
target_link_libraries(leptjson_test leptjson)
add_test(leptjson_test leptjson_test)