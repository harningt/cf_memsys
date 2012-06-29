cmake_minimum_required(VERSION 2.8)
project("libarena" C)

include(WriteBasicConfigVersionFile)

SET(LIBARENA_VERSION 0.3.4)

SET(LIBARENA_SRC ../libarena/src)

set(SOURCES
    ${LIBARENA_SRC}/arena.c
    ${LIBARENA_SRC}/pool.c
    ${LIBARENA_SRC}/proto.c
    ${LIBARENA_SRC}/util.c
)
set(PUBLIC_HEADERS
    ${LIBARENA_SRC}/align.h
    ${LIBARENA_SRC}/arena.h
    ${LIBARENA_SRC}/pool.h
    ${LIBARENA_SRC}/proto.h
    ${LIBARENA_SRC}/queue.h
    ${LIBARENA_SRC}/rbits.h
    ${LIBARENA_SRC}/util.h
)
set(HEADERS
    ${PUBLIC_HEADERS}
)
include_directories(${LIBARENA_SRC})

add_definitions(-DLIBARENA_SOURCE)

add_library(arena STATIC ${SOURCES} ${HEADERS})

# Setup header layout
file(COPY ${PUBLIC_HEADERS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/arena)

get_filename_component(LIBARENA_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR} ABSOLUTE)

configure_file(libarena-config.cmake.in ${CF_MEMSYS_MODULE_PATH}/libarena-config.cmake @ONLY)
export(TARGETS arena APPEND FILE ${CF_MEMSYS_MODULE_PATH}/libarena-config.cmake)
WRITE_BASIC_CONFIG_VERSION_FILE(
    ${CF_MEMSYS_MODULE_PATH}/libarena-config-version.cmake
    VERSION ${LIBARENA_VERSION}
    COMPATIBILITY SameMajorVersion)
