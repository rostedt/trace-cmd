# Check if cmake has the required version
cmake_minimum_required(VERSION 2.8.11 FATAL_ERROR)

# Set the name and version of the project
project(kernel-shark-qt)

set(KS_VERSION_MAJOR 0)
set(KS_VERSION_MINOR 7)
set(KS_VERSION_PATCH 1)
set(KS_VERSION_STRING ${KS_VERSION_MAJOR}.${KS_VERSION_MINOR}.${KS_VERSION_PATCH})
message("\n project: Kernel Shark: (version: ${KS_VERSION_STRING})\n")

set(KS_DIR ${CMAKE_SOURCE_DIR})

include(${KS_DIR}/build/FindTraceCmd.cmake)

find_package(Doxygen)

set(LIBRARY_OUTPUT_PATH    "${KS_DIR}/lib")
set(EXECUTABLE_OUTPUT_PATH "${KS_DIR}/bin")

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -Wall -pthread")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11 -pthread")

include_directories(${KS_DIR}/src/
                    ${KS_DIR}/build/src/
                    ${TRACECMD_INCLUDE_DIR}
                    ${TRACEEVENT_INCLUDE_DIR})

message("")
message(STATUS "C flags      : " ${CMAKE_C_FLAGS})
message(STATUS "CXX flags    : " ${CMAKE_CXX_FLAGS})
message(STATUS "Linker flags : " ${CMAKE_EXE_LINKER_FLAGS})

add_subdirectory(${KS_DIR}/src)
add_subdirectory(${KS_DIR}/examples)

if (_DOXYGEN_DOC AND DOXYGEN_FOUND)

    message("\n doxygen documentation ...")
    add_custom_target(doc ALL)
    add_custom_command(TARGET doc
                       COMMAND doxygen dox_config > dox_build.log
                       WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/doc)

    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
                                          "${KS_DIR}/doc/dox_build.log"
                                          "${KS_DIR}/doc/html"
                                          "${KS_DIR}/doc/latex")

endif ()

message("")
