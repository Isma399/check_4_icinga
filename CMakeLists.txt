cmake_minimum_required(VERSION 3.5)
project("check-4-icinga" VERSION 0.0.1 LANGUAGES C)

## Compiler Flags
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O2")

## Module Include
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules" "${CMAKE_MODULE_PATH}")

## Force Out Of Tree
include(MacroOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out tree build.")

## Output Directories
include(GNUInstallDirs)
set(ARCHIVE_DIR ${CMAKE_INSTALL_LIBDIR})
set(LIBRARY_DIR ${CMAKE_INSTALL_LIBDIR})
set(RUNTIME_DIR ${CMAKE_INSTALL_BINDIR})

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

## Uninstall Target
configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)
add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

##
include(FindNetSnmp)

add_subdirectory("${PROJECT_SOURCE_DIR}/src")

## Package
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES "/\\\\..*$;~$;${CMAKE_SOURCE_DIR}/build/")
include(CPack)