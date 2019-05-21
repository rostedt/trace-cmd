# Check if cmake has the required version
cmake_minimum_required(VERSION 2.8.11 FATAL_ERROR)

# Set the name and version of the project
project(kernel-shark)

set(KS_APP_NAME "kernelshark")
set(KS_VERSION_MAJOR 0)
set(KS_VERSION_MINOR 9)
set(KS_VERSION_PATCH 8)
set(KS_VERSION_STRING ${KS_VERSION_MAJOR}.${KS_VERSION_MINOR}.${KS_VERSION_PATCH})
message("\n project: Kernel Shark: (version: ${KS_VERSION_STRING})\n")

set(KS_DIR ${CMAKE_SOURCE_DIR})

include(${KS_DIR}/build/FindTraceCmd.cmake)
include(${KS_DIR}/build/FindJSONC.cmake)

find_package(Doxygen)

set(OpenGL_GL_PREFERENCE LEGACY)
find_package(OpenGL)
find_package(GLUT)

find_package(Qt5Widgets 5.7.1)
find_package(Qt5Network)
if (Qt5Widgets_FOUND)

    message(STATUS "Found Qt5Widgets:  (version ${Qt5Widgets_VERSION})")

endif (Qt5Widgets_FOUND)

set(LIBRARY_OUTPUT_PATH    "${KS_DIR}/lib")
set(EXECUTABLE_OUTPUT_PATH "${KS_DIR}/bin")

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -Wall -g -pthread -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g -std=c++11 -pthread -fPIC")

if(NOT _INSTALL_PREFIX)
	set(_INSTALL_PREFIX "/usr/local")
endif()

set(KS_PLUGIN_INSTALL_PREFIX ${_INSTALL_PREFIX}/lib/${KS_APP_NAME}/plugins/)
set(KS_ICON ksharkicon.png)

if (NOT _DEBUG)

	set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -O2")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

endif (NOT _DEBUG)

SET(CMAKE_INSTALL_RPATH "${_INSTALL_PREFIX}/lib/${KS_APP_NAME}/")
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

include_directories(${KS_DIR}/src/
                    ${KS_DIR}/build/src/
                    ${JSONC_INCLUDE_DIR}
                    ${TRACECMD_INCLUDE_DIR})

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

configure_file( ${KS_DIR}/build/ks.desktop.cmake
                ${KS_DIR}/${KS_APP_NAME}.desktop)

configure_file( ${KS_DIR}/build/org.freedesktop.kshark-record.policy.cmake
                ${KS_DIR}/org.freedesktop.kshark-record.policy)

message("")
