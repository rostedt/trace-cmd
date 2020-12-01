if(Qt5Widgets_FOUND AND Qt5Network_FOUND)
  install(
    PROGRAMS kshark-su-record
    DESTINATION ${CMAKE_INSTALL_BINDIR}/
  )
endif(Qt5Widgets_FOUND AND Qt5Network_FOUND)
