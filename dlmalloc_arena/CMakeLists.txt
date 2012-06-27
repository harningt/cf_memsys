cmake_minimum_required(VERSION 2.8)
project("dlmalloc_arena" C)

set(DLMALLOC_ARENA_VERSION 0.0.0)

include(WriteBasicConfigVersionFile)

set(SOURCES
    dlmalloc.c
    dlmalloc_arena.c
)
set(PUBLIC_HEADERS
    dlmalloc_arena.h
)
set(HEADERS
    ${PUBLIC_HEADERS}
    dlmalloc.h
    dlmalloc_arena_setup.h
)

include_directories(.)
add_library(dlmalloc_arena STATIC ${SOURCES} ${HEADERS})

add_executable(dlmalloc_arena_test ${SOURCES} ${HEADERS})

find_package(libarena REQUIRED CONFIG PATHS ${CF_MODULE_PATH})

include_directories(${LIBARENA_INCLUDE_DIRS})

target_link_libraries(dlmalloc_arena ${LIBARENA_LIBRARIES})
target_link_libraries(dlmalloc_arena_test ${LIBARENA_LIBRARIES})

set_target_properties(dlmalloc_arena_test
    PROPERTIES
    COMPILE_FLAGS -DDLMALLOC_ARENA_MAIN
)

# Setup header layout
file(COPY ${PUBLIC_HEADERS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

get_filename_component(DLMALLOC_ARENA_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR} ABSOLUTE)
configure_file(dlmalloc_arena-config.cmake.in ${CF_MODULE_PATH}/dlmalloc_arena-config.cmake @ONLY)
export(TARGETS dlmalloc_arena APPEND FILE ${CF_MODULE_PATH}/dlmalloc_arena-config.cmake)
WRITE_BASIC_CONFIG_VERSION_FILE(
    ${CF_MODULE_PATH}/dlmalloc_arena-config-version.cmake
    VERSION ${DLMALLOC_ARENA_VERSION}
    COMPATIBILITY SameMajorVersion)

