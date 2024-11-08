cmake_minimum_required(VERSION 3.26)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION True)

project(
    sync
    DESCRIPTION "Ret-Sync"
    HOMEPAGE_URL https://github.com/bootleg/ret-sync
)
set(PROJECT_AUTHOR bootleg)
set(PROJECT_LICENSE GPLv3)

add_subdirectory(ext_windbg)
add_subdirectory(ext_x64dbg)
