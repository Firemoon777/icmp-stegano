cmake_minimum_required(VERSION 3.22)
project(icmp C)

set(CMAKE_C_STANDARD 11)

add_executable(icmp_server src/server.c
        src/icmp.c)
add_executable(icmp_client src/client.c
        src/icmp.c)

target_include_directories(icmp_client PRIVATE include)
target_include_directories(icmp_server PRIVATE include)