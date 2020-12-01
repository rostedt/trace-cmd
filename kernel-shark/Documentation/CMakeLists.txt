if(${DOXYGEN_FOUND})
  message(STATUS "Build doxygen documentation ...")
  add_custom_target(doc ALL)
  add_custom_command(
    TARGET doc
    COMMAND doxygen dox_config > dox_build.log
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/Documentation/doxygen
  )
  add_custom_command(
    TARGET doc
    COMMAND mv html/ latex/ dox_build.log ${CMAKE_CURRENT_BINARY_DIR}/
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/Documentation/doxygen
  )
endif()
