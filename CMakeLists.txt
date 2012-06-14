cmake_minimum_required(VERSION 2.8)
project(cf_memsys C)

SET(CF_MODULE_PATH ${CMAKE_CURRENT_BINARY_DIR}/Modules)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CF_MODULE_PATH})

ADD_SUBDIRECTORY(libarena_cmake)
