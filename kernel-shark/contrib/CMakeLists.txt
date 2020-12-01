configure_file(
  ${PROJECT_NAME}.desktop.in
  ${PROJECT_NAME}.desktop
)

configure_file(
  org.freedesktop.kshark-record.policy.in
  org.freedesktop.kshark-record.policy
)

install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.desktop"
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/applications/
)

install(
  FILES "icons/${PROJECT_NAME}.svg"
  DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps/"
)

install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/org.freedesktop.kshark-record.policy"
  DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/polkit-1/actions/"
)
