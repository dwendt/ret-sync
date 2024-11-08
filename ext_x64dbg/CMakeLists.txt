project(sync-x64dbg LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

set(CXX_STANDARD 20)

include(FetchContent)
message(STATUS "Fetching x64dbg...")
FetchContent_Declare(x64dbg
	URL
		"https://downloads.sourceforge.net/project/x64dbg/snapshots/snapshot_2023-06-10_18-05.zip"
	URL_HASH
		SHA1=04468bd61fb36d6b10d17f342f03ef12f5b2ce62
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
