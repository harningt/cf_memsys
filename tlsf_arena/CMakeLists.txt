cmake_minimum_required(VERSION 2.8)
project("tlsf_arena" C)

set(TLSF_ARENA_VERSION 0.0.0)

set(SOURCES
    tlsf_arena.c
    tlsf/tlsf.c
)

set(PUBLIC_HEADERS
    tlsf_arena.h
)
set(HEADERS
    ${PUBLIC_HEADERS}
    tlsf/tlsf.h
    tlsf/tlsfbits.h
)

include_directories(tlsf)
add_library(tlsf_arena STATIC ${SOURCES} ${HEADERS})
add_executable(tlsf_arena_test ${SOURCES} ${HEADERS})

find_package(libarena REQUIRED CONFIG PATHS ${CMAKE_MODULE_PATH})

include_directories(${LIBARENA_INCLUDE_DIRS})

target_link_libraries(tlsf_arena ${LIBARENA_LIBRARIES})
target_link_libraries(tlsf_arena_test ${LIBARENA_LIBRARIES})

set_target_properties(tlsf_arena_test
    PROPERTIES
    COMPILE_FLAGS -DTLSF_ARENA_MAIN
)

# Setup header layout
file(COPY ${PUBLIC_HEADERS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

get_filename_component(TLSF_ARENA_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR} ABSOLUTE)
configure_file(tlsf_arena-config.cmake.in ${CF_MEMSYS_MODULE_PATH}/tlsf_arena-config.cmake @ONLY)
export(TARGETS tlsf_arena APPEND FILE ${CF_MEMSYS_MODULE_PATH}/tlsf_arena-config.cmake)
WRITE_BASIC_CONFIG_VERSION_FILE(
    ${CF_MEMSYS_MODULE_PATH}/tlsf_arena-config-version.cmake
    VERSION ${TLSF_ARENA_VERSION}
    COMPATIBILITY SameMajorVersion)

