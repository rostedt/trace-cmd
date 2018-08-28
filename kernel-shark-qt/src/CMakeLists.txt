message("\n src ...")

message(STATUS "libkshark")
add_library(kshark SHARED libkshark.c
                          libkshark-model.c
                          libkshark-configio.c
                          libkshark-collection.c)

target_link_libraries(kshark ${CMAKE_DL_LIBS}
                             ${JSONC_LIBRARY}
                             ${TRACEEVENT_LIBRARY}
                             ${TRACECMD_LIBRARY})

set_target_properties(kshark  PROPERTIES SUFFIX	".so.${KS_VERSION_STRING}")

if (OPENGL_FOUND AND GLUT_FOUND)

    message(STATUS "libkshark-plot")
    add_library(kshark-plot  SHARED  libkshark-plot.c
                                     KsPlotTools.cpp)

    target_link_libraries(kshark-plot  kshark
                                       ${OPENGL_LIBRARIES}
                                       ${GLUT_LIBRARY})

    set_target_properties(kshark-plot PROPERTIES  SUFFIX ".so.${KS_VERSION_STRING}")

endif (OPENGL_FOUND AND GLUT_FOUND)

configure_file( ${KS_DIR}/build/deff.h.cmake
                ${KS_DIR}/src/KsDeff.h)
