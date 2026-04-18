cmake_minimum_required(VERSION 3.11)
project(deadcodedebug)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FindPkgConfig)
pkg_check_modules(CAPSTONE REQUIRED capstone)

add_executable(deadcodedebug src/main.cpp src/tracer.cpp src/process.cpp)
target_link_libraries(deadcodedebug ${CAPSTONE_LIBRARIES} ntdll)