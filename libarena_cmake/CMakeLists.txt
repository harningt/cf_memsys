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
set(HEADERS
    ${LIBARENA_SRC}/align.h
    ${LIBARENA_SRC}/arena.h
    ${LIBARENA_SRC}/pool.h
    ${LIBARENA_SRC}/proto.h
    ${LIBARENA_SRC}/queue.h
    ${LIBARENA_SRC}/rbits.h
    ${LIBARENA_SRC}/util.h
)
include_directories(${LIBARENA_SRC})

add_definitions(-DLIBARENA_SOURCE)

add_library(arena STATIC ${SOURCES} ${HEADERS})

SET(LIBARENA_LIBRARIES arena)
GET_FILENAME_COMPONENT(LIBARENA_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/${LIBARENA_SRC} ABSOLUTE)

configure_file(libarena-config.cmake.in ${CF_MODULE_PATH}/libarena-config.cmake @ONLY)
export(TARGETS arena APPEND FILE ${CF_MODULE_PATH}/libarena-config.cmake)
WRITE_BASIC_CONFIG_VERSION_FILE(${CF_MODULE_PATH}/libarena-config-version.cmake VERSION ${LIBARENA_VERSION} COMPATIBILITY SameMajorVersion)
