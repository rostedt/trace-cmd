# Find traceevent and trace-cmd
# This module finds an installed trace-cmd package.
#
# It sets the following variables:
#  TRACEEVENT_INCLUDE_DIR, where to find traceevent header.
#  TRACEEVENT_LIBRARY_DIR , where to find the traceevent library.
#  TRACEEVENT_LIBRARY, traceevent the library.
#  TRACEEVENT_FOUND, If false, do not try to use traceevent.
#
#  TRACECMD_INCLUDE_DIR, where to find trace-cmd header.
#  TRACECMD_LIBRARY_DIR , where to find the trace-cmd library.
#  TRACECMD_LIBRARY, the trace-cmd library.
#  TRACECMD_FOUND, If false, do not try to use trace-cmd.

# MESSAGE(" Looking for trace-cmd ...")

find_path(TRACECMD_BIN_DIR      NAMES  trace-cmd
                                PATHS  $ENV{TRACE_CMD}/tracecmd/
                                       ${CMAKE_SOURCE_DIR}/../tracecmd/)

find_path(TRACECMD_INCLUDE_DIR  NAMES  trace-cmd.h
                                PATHS  $ENV{TRACE_CMD}/include/trace-cmd/
                                       ${CMAKE_SOURCE_DIR}/../include/trace-cmd/)

find_path(TRACECMD_LIBRARY_DIR  NAMES  libtracecmd.a
                                PATHS  $ENV{TRACE_CMD}/lib/trace-cmd/
                                       ${CMAKE_SOURCE_DIR}/../lib/trace-cmd/)

IF (TRACECMD_INCLUDE_DIR AND TRACECMD_LIBRARY_DIR)

  SET(TRACECMD_FOUND TRUE)
  SET(TRACECMD_LIBRARY "${TRACECMD_LIBRARY_DIR}/libtracecmd.a")

ENDIF (TRACECMD_INCLUDE_DIR AND TRACECMD_LIBRARY_DIR)

IF (TRACECMD_FOUND)

  MESSAGE(STATUS "Found trace-cmd: ${TRACECMD_LIBRARY}")

ELSE (TRACECMD_FOUND)

  MESSAGE(FATAL_ERROR "\nCould not find trace-cmd!\n")

ENDIF (TRACECMD_FOUND)


find_path(TRACEEVENT_INCLUDE_DIR  NAMES  event-parse.h
                                  PATHS  $ENV{TRACE_CMD}/include/traceevent/
                                         ${CMAKE_SOURCE_DIR}/../include/traceevent/)

find_path(TRACEEVENT_LIBRARY_DIR  NAMES  libtraceevent.a
                                  PATHS  $ENV{TRACE_CMD}/lib/traceevent/
                                         ${CMAKE_SOURCE_DIR}/../lib/traceevent/)

IF (TRACEEVENT_INCLUDE_DIR AND TRACEEVENT_LIBRARY_DIR)

  SET(TRACEEVENT_FOUND TRUE)
  SET(TRACEEVENT_LIBRARY "${TRACEEVENT_LIBRARY_DIR}/libtraceevent.a")

ENDIF (TRACEEVENT_INCLUDE_DIR AND TRACEEVENT_LIBRARY_DIR)

IF (TRACEEVENT_FOUND)

  MESSAGE(STATUS "Found traceevent: ${TRACEEVENT_LIBRARY}")

ELSE (TRACEEVENT_FOUND)

  MESSAGE(FATAL_ERROR "\nCould not find libtraceevent!\n")

ENDIF (TRACEEVENT_FOUND)
