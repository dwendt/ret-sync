project(sync-x64dbg LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

set(CXX_STANDARD 20)

include(FetchContent)
set(X64DBG_SNAPSHOT_TIMESTAMP "2024-10-18_19-09")
message(STATUS "Setting up x64dbg-${X64DBG_SNAPSHOT_TIMESTAMP}")
FetchContent_Declare(
    x64dbg
    URL https://github.com/x64dbg/x64dbg/releases/download/snapshot/snapshot_${X64DBG_SNAPSHOT_TIMESTAMP}.zip
    URL_HASH SHA1=E84588749510EC9075603EDD12AC22C9FC7C7E03
)
FetchContent_MakeAvailable(x64dbg)
include("cmake/x64dbg.cmake")

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(PROJECT_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})
set(SOURCE_FILES
    ${PROJECT_ROOT_DIR}/x64dbg_sync/core.cpp
    ${PROJECT_ROOT_DIR}/x64dbg_sync/sync.cpp
    ${PROJECT_ROOT_DIR}/x64dbg_sync/tunnel.cpp
)

x64dbg_plugin(${PROJECT_NAME} ${SOURCE_FILES})
target_compile_definitions(${PROJECT_NAME} PRIVATE _USRDLL X64DBG_SYNC_EXPORTS)
target_include_directories(${PROJECT_NAME} PRIVATE $<TARGET_PROPERTY:x64dbg,INCLUDE_DIRECTORIES>)
target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE
    ws2_32.lib
    crypt32.lib
    Shlwapi.lib
    dbgeng.lib
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_libraries(
        ${PROJECT_NAME}
        PRIVATE
        ${x64dbg_SOURCE_DIR}/pluginsdk/x64dbg.lib
        ${x64dbg_SOURCE_DIR}/pluginsdk/x64bridge.lib)
else()
    target_link_libraries(
        ${PROJECT_NAME}
        PRIVATE
        ${x64dbg_SOURCE_DIR}/pluginsdk/x32dbg.lib
        ${x64dbg_SOURCE_DIR}/pluginsdk/x32bridge.lib)
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION ${PROJECT_NAME}/Library)
install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION Library/Debug OPTIONAL)
