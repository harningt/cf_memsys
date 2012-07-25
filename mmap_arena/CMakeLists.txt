cmake_minimum_required(VERSION 2.8)
project("mmap_arena" C)

set(MMAP_ARENA_VERSION 0.0.0)

set(SOURCES
    mmap_arena.c
)

set(PUBLIC_HEADERS
    mmap_arena.h
)
set(HEADERS
    ${PUBLIC_HEADERS}
)

include_directories(tlsf)
add_library(mmap_arena STATIC ${SOURCES} ${HEADERS})
add_executable(mmap_arena_test ${SOURCES} ${HEADERS})

find_package(libarena REQUIRED CONFIG PATHS ${CMAKE_MODULE_PATH})

include_directories(${LIBARENA_INCLUDE_DIRS})

target_link_libraries(mmap_arena ${LIBARENA_LIBRARIES})
target_link_libraries(mmap_arena_test ${LIBARENA_LIBRARIES})

set_target_properties(mmap_arena_test
    PROPERTIES
    COMPILE_FLAGS -DMMAP_ARENA_MAIN
)

# Setup header layout
file(COPY ${PUBLIC_HEADERS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

get_filename_component(MMAP_ARENA_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR} ABSOLUTE)
configure_file(mmap_arena-config.cmake.in ${CF_MEMSYS_MODULE_PATH}/mmap_arena-config.cmake @ONLY)
export(TARGETS mmap_arena APPEND FILE ${CF_MEMSYS_MODULE_PATH}/mmap_arena-config.cmake)
WRITE_BASIC_CONFIG_VERSION_FILE(
    ${CF_MEMSYS_MODULE_PATH}/mmap_arena-config-version.cmake
    VERSION ${MMAP_ARENA_VERSION}
    COMPATIBILITY SameMajorVersion)

