message("\n src ...")

message(STATUS "libkshark")
add_library(kshark SHARED libkshark.c
                          libkshark-model.c
                          libkshark-plugin.c
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

if (Qt5Widgets_FOUND AND Qt5Network_FOUND)

    message(STATUS "libkshark-gui")
    set (ks-guiLib_hdr  KsUtils.hpp
                        KsModels.hpp
                        KsDualMarker.hpp
                        KsWidgetsLib.hpp)

    QT5_WRAP_CPP(ks-guiLib_hdr_moc ${ks-guiLib_hdr})

    add_library(kshark-gui  SHARED  ${ks-guiLib_hdr_moc}    KsUtils.cpp
                                                            KsModels.cpp
                                                            KsDualMarker.cpp
                                                            KsWidgetsLib.cpp)

    target_link_libraries(kshark-gui kshark-plot
                                     ${CMAKE_DL_LIBS}
                                     ${TRACEEVENT_LIBRARY}
                                     ${TRACECMD_LIBRARY}
                                     Qt5::Widgets
                                     Qt5::Network)

    set_target_properties(kshark-gui PROPERTIES  SUFFIX ".so.${KS_VERSION_STRING}")

endif (Qt5Widgets_FOUND AND Qt5Network_FOUND)

add_subdirectory(plugins)

configure_file( ${KS_DIR}/build/deff.h.cmake
                ${KS_DIR}/src/KsCmakeDef.hpp)
