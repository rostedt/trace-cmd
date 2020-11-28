# Check if cmake has the required version
cmake_minimum_required(VERSION 3.4.3 FATAL_ERROR)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 2)
set(VERSION_PATCH 0)

project(
  kernelshark
  VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
)

include(GNUInstallDirs)
include(cmake/FindTraceCmd.cmake)
include(cmake/FindJSONC.cmake)

set(OpenGL_GL_PREFERENCE LEGACY)
find_package(OpenGL)
find_package(GLUT)
find_package(Qt5Widgets 5.7.1)
if (Qt5Widgets_FOUND)
    message(STATUS "Found Qt5Widgets:  (version ${Qt5Widgets_VERSION})")
endif (Qt5Widgets_FOUND)
find_package(Qt5Network)
find_package(Doxygen)
find_program(DO_AS_ROOT pkexec)

option("DOCUMENTATION" OFF)

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -Wall -pthread -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11 -pthread -fPIC")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif (NOT CMAKE_BUILD_TYPE)

message("\n Build type: ${CMAKE_BUILD_TYPE}")

if (NOT CMAKE_C_FLAGS_PACKAGE)
    set(CMAKE_C_FLAGS_PACKAGE "-O3")
endif (NOT CMAKE_C_FLAGS_PACKAGE)

if (NOT CMAKE_CXX_FLAGS_PACKAGE)
    set(CMAKE_CXX_FLAGS_PACKAGE "-O3")
endif (NOT CMAKE_CXX_FLAGS_PACKAGE)

set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/")

if(CMAKE_BUILD_TYPE MATCHES Package)

    set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

else(CMAKE_BUILD_TYPE MATCHES Package)

    set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

endif(CMAKE_BUILD_TYPE MATCHES Package)

include_directories(
  src/
  ../lib/trace-cmd/include/private/
  ${CMAKE_CURRENT_BINARY_DIR}/src/
  ${JSONC_INCLUDE_DIR}
  ${TRACECMD_INCLUDE_DIR}
  ${TRACEFS_INCLUDE_DIR}
)

message(STATUS "C flags      : " ${CMAKE_C_FLAGS})
message(STATUS "CXX flags    : " ${CMAKE_CXX_FLAGS})
message(STATUS "Linker flags : " ${CMAKE_EXE_LINKER_FLAGS})

add_definitions(
  -DKS_VERSION_STRING="${PROJECT_VERSION}"
  -D_INSTALL_PREFIX="${CMAKE_INSTALL_PREFIX}"
  -DKS_PLUGIN_INSTALL_PREFIX="${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/plugins/"
  -DTRACECMD_EXECUTABLE="${TRACECMD_EXECUTABLE}"
)

add_subdirectory(src)
add_subdirectory(bin)
add_subdirectory(examples)
add_subdirectory(contrib)
add_subdirectory(Documentation)
