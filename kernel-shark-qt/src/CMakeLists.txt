message("\n src ...")

message(STATUS "libkshark")
add_library(kshark SHARED libkshark.c)

target_link_libraries(kshark ${CMAKE_DL_LIBS}
                             ${TRACEEVENT_LIBRARY}
                             ${TRACECMD_LIBRARY})

set_target_properties(kshark  PROPERTIES SUFFIX	".so.${KS_VERSION_STRING}")

configure_file( ${KS_DIR}/build/deff.h.cmake
                ${KS_DIR}/src/KsDeff.h)
