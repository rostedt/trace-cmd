message(STATUS "Building src ...")

configure_file(
  deff.h.in
  KsCmakeDef.hpp
)

message(STATUS "Building libkshark")
add_library(
  kshark
  SHARED
  libkshark.c
  libkshark-model.c
  libkshark-plugin.c
  libkshark-configio.c
  libkshark-collection.c
)

target_link_libraries(
  kshark
  ${TRACECMD_LIBRARY}
  ${TRACEFS_LIBRARY}
  ${TRACEEVENT_LIBRARY}
  ${JSONC_LIBRARY}
  ${CMAKE_DL_LIBS}
)

set_target_properties(
  kshark
  PROPERTIES
  SUFFIX
  ".so.${PROJECT_VERSION}"
)

install(
  TARGETS kshark
  LIBRARY
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/
)

if(OPENGL_FOUND AND GLUT_FOUND)
  message(STATUS "Build libkshark-plot")
  add_library(
    kshark-plot
    SHARED
    libkshark-plot.c
    KsPlotTools.cpp
  )
  target_link_libraries(
    kshark-plot
    kshark
    ${GLUT_LIBRARY}
    ${OPENGL_LIBRARIES}
  )
  set_target_properties(
    kshark-plot
    PROPERTIES
    SUFFIX
    ".so.${PROJECT_VERSION}"
  )
  install(
    TARGETS kshark-plot
    LIBRARY
    DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}
)
endif(OPENGL_FOUND AND GLUT_FOUND)

if(Qt5Widgets_FOUND AND Qt5Network_FOUND)
  message(STATUS "Build libkshark-gui")
  set(
    GUILIB_HEADERS
    KsUtils.hpp
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
    KsAdvFilteringDialog.hpp
  )
  QT5_WRAP_CPP(GUILIB_HEADERS_MOC ${GUILIB_HEADERS})

  add_library(
    kshark-gui
    SHARED
    ${GUILIB_HEADERS_MOC}
    KsUtils.cpp
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
    KsAdvFilteringDialog.cpp
  )

  target_link_libraries(
    kshark-gui
    kshark-plot
    Qt5::Widgets
    Qt5::Network
  )

  set_target_properties(
    kshark-gui
    PROPERTIES
    SUFFIX
    ".so.${PROJECT_VERSION}"
  )

  message(STATUS "Building ${PROJECT_NAME}")
  add_executable(${PROJECT_NAME} kernelshark.cpp)
  target_link_libraries(${PROJECT_NAME} kshark-gui)

  message(STATUS "Building kshark-record")
  add_executable(kshark-record kshark-record.cpp)
  target_link_libraries(kshark-record kshark-gui)

  install(
    TARGETS ${PROJECT_NAME} kshark-record kshark-gui
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/
  )
endif(Qt5Widgets_FOUND AND Qt5Network_FOUND)

add_subdirectory(plugins)
