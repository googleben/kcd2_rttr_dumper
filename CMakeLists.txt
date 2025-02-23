cmake_minimum_required(VERSION 3.30)
project(kcd2_rttr_dumper)

set(CMAKE_CXX_STANDARD 20)

add_executable(kcd2_rttr_dumper main.cpp
        DumpHandler.cpp
        DumpHandler.h)
include_directories(cccapstone/capstone/include cccapstone/cppbindings)
target_link_libraries(kcd2_rttr_dumper  ${CMAKE_CURRENT_SOURCE_DIR}/cccapstone/capstone/cmake-build-release/capstone.lib shlwapi)
#set(CMAKE_CXX_FLAGS_RELEASE "/O2")