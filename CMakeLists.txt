project(t)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} O0 -Wall -g -ggdb")

add_executable(t size.cc)

target_link_libraries(t libssl.a)
target_link_libraries(t -lcrypto)
target_link_libraries(t -ldl)
