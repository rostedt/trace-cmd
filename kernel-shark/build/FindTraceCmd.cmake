# Find traceevent and trace-cmd
# This module finds an installed trace-cmd package.
#
# It sets the following variables:
#  TRACEEVENT_LIBRARY, traceevent the library.
#  TRACEEVENT_FOUND, If false, do not try to use traceevent.
#
#  TRACECMD_INCLUDE_DIR, where to find trace-cmd header.
#  TRACECMD_LIBRARY, the trace-cmd library.
#  TRACECMD_FOUND, If false, do not try to use trace-cmd.

# MESSAGE(" Looking for trace-cmd ...")

# First search in the user provided paths.
find_path(TRACECMD_BIN_DIR      NAMES  trace-cmd
                                PATHS  $ENV{TRACE_CMD}/tracecmd/
                                       ${CMAKE_SOURCE_DIR}/../tracecmd/
                                NO_DEFAULT_PATH)

find_path(TRACECMD_INCLUDE_DIR  NAMES  trace-cmd/trace-cmd.h
                                PATHS  $ENV{TRACE_CMD}/include/
                                       ${CMAKE_SOURCE_DIR}/../include/
                                NO_DEFAULT_PATH)

find_library(TRACECMD_LIBRARY   NAMES  trace-cmd/libtracecmd.a
                                PATHS  $ENV{TRACE_CMD}/lib/
                                       ${CMAKE_SOURCE_DIR}/../lib/
                                NO_DEFAULT_PATH)

find_library(TRACEEVENT_LIBRARY NAMES  traceevent/libtraceevent.a
                                PATHS  $ENV{TRACE_CMD}/lib/
                                       ${CMAKE_SOURCE_DIR}/../lib/
                                NO_DEFAULT_PATH)

# If not found, search in the default system paths. Note that if the previous
# search was successful "find_path" will do nothing this time.
find_path(TRACECMD_BIN_DIR      NAMES  trace-cmd)
find_path(TRACECMD_INCLUDE_DIR  NAMES  trace-cmd/trace-cmd.h)
find_library(TRACECMD_LIBRARY   NAMES  trace-cmd/libtracecmd.so)
find_library(TRACEEVENT_LIBRARY NAMES  traceevent/libtraceevent.so)

IF (TRACECMD_INCLUDE_DIR AND TRACECMD_LIBRARY)

  SET(TRACECMD_FOUND TRUE)

ENDIF (TRACECMD_INCLUDE_DIR AND TRACECMD_LIBRARY)

IF (TRACECMD_FOUND)

  MESSAGE(STATUS "Found trace-cmd: ${TRACECMD_LIBRARY}")

ELSE (TRACECMD_FOUND)

  MESSAGE(FATAL_ERROR "\nCould not find trace-cmd!\n")

ENDIF (TRACECMD_FOUND)

IF (TRACEEVENT_LIBRARY)

  SET(TRACEEVENT_FOUND TRUE)

ENDIF (TRACEEVENT_LIBRARY)

IF (TRACEEVENT_FOUND)

  MESSAGE(STATUS "Found traceevent: ${TRACEEVENT_LIBRARY}")

ELSE (TRACEEVENT_FOUND)

  MESSAGE(FATAL_ERROR "\nCould not find libtraceevent!\n")

ENDIF (TRACEEVENT_FOUND)
