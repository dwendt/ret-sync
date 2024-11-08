project(sync-windbg LANGUAGES CXX)

set(PROJECT_AUTHOR bootleg)
set(PROJECT_LICENSE GPLv3)
set(CXX_STANDARD 20)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(PROJECT_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})
set(SOURCE_FILES
    ${PROJECT_ROOT_DIR}/sync/outputcallback.cpp
    ${PROJECT_ROOT_DIR}/sync/sync.cpp
    ${PROJECT_ROOT_DIR}/sync/tunnel.cpp
    ${PROJECT_ROOT_DIR}/sync/sync.def
)

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})
set_source_files_properties(${PROJECT_ROOT_DIR}/sync/sync.def PROPERTIES HEADER_FILE_ONLY TRUE)
target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_ROOT_DIR}/sync)
target_link_libraries(
    ${PROJECT_NAME}
    ws2_32.lib
    crypt32.lib
    Shlwapi.lib
    dbgeng.lib
)

if(MSVC)
    target_link_options(${PROJECT_NAME} PUBLIC /DEF:${PROJECT_ROOT_DIR}/sync/sync.def)
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION ${PROJECT_NAME}/Library)
install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION Library/Debug OPTIONAL)
