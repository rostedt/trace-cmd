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
                        KsGLWidget.hpp
                        KsSearchFSM.hpp
                        KsDualMarker.hpp
                        KsWidgetsLib.hpp
                        KsTraceGraph.hpp
                        KsTraceViewer.hpp
                        KsMainWindow.hpp
                        KsCaptureDialog.hpp
                        KsQuickContextMenu.hpp
                        KsAdvFilteringDialog.hpp)

    QT5_WRAP_CPP(ks-guiLib_hdr_moc ${ks-guiLib_hdr})

    add_library(kshark-gui  SHARED  ${ks-guiLib_hdr_moc}    KsUtils.cpp
                                                            KsModels.cpp
                                                            KsSession.cpp
                                                            KsGLWidget.cpp
                                                            KsSearchFSM.cpp
                                                            KsDualMarker.cpp
                                                            KsWidgetsLib.cpp
                                                            KsTraceGraph.cpp
                                                            KsTraceViewer.cpp
                                                            KsMainWindow.cpp
                                                            KsCaptureDialog.cpp
                                                            KsQuickContextMenu.cpp
                                                            KsAdvFilteringDialog.cpp)

    target_link_libraries(kshark-gui kshark-plot
                                     ${CMAKE_DL_LIBS}
                                     ${TRACEEVENT_LIBRARY}
                                     ${TRACECMD_LIBRARY}
                                     Qt5::Widgets
                                     Qt5::Network)

    set_target_properties(kshark-gui PROPERTIES  SUFFIX ".so.${KS_VERSION_STRING}")

    message(STATUS "kernelshark")
    add_executable(kernelshark          kernelshark.cpp)
    target_link_libraries(kernelshark   kshark-gui)

    message(STATUS "kshark-record")
    add_executable(kshark-record        kshark-record.cpp)
    target_link_libraries(kshark-record kshark-gui)

    install(TARGETS kernelshark kshark-record kshark kshark-plot kshark-gui
            RUNTIME DESTINATION ${_INSTALL_PREFIX}/bin/
            LIBRARY DESTINATION ${_INSTALL_PREFIX}/lib/kshark/)

    install(FILES "${KS_DIR}/kernelshark.desktop"
            DESTINATION /usr/share/applications/)

    install(FILES "${KS_DIR}/org.freedesktop.kshark-record.policy"
            DESTINATION /usr/share/polkit-1/actions/)

    install(PROGRAMS "${KS_DIR}/bin/kshark-su-record"
            DESTINATION ${_INSTALL_PREFIX}/bin/)

endif (Qt5Widgets_FOUND AND Qt5Network_FOUND)

add_subdirectory(plugins)

find_program(DO_AS_ROOT pkexec)

configure_file( ${KS_DIR}/build/deff.h.cmake
                ${KS_DIR}/src/KsCmakeDef.hpp)
