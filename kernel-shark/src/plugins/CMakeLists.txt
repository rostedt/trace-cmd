message(STATUS "Building plugins ...")

function(build_plugin)
  set(options)
  set(oneValueArgs NAME)
  set(multiValueArgs SOURCE)
  cmake_parse_arguments(
    ADD_PLUGIN "${options}"
    ${oneValueArgs}
    ${multiValueArgs}
    ${ARGN}
  )

  message(STATUS ${ADD_PLUGIN_NAME})

  add_library(${ADD_PLUGIN_NAME} SHARED ${ADD_PLUGIN_SOURCE})
  set_target_properties(${ADD_PLUGIN_NAME} PROPERTIES PREFIX "plugin-")
  target_link_libraries(${ADD_PLUGIN_NAME} kshark)
endfunction()

set(PLUGIN_LIST "")
build_plugin(
  NAME sched_events
  SOURCE sched_events.c SchedEvents.cpp
)
list(APPEND PLUGIN_LIST "sched_events default") # This plugin will be loaded by default
# list(APPEND PLUGIN_LIST "sched_events") # This plugin isn't loaded by default

build_plugin(
  NAME missed_events
  SOURCE missed_events.c MissedEvents.cpp
)
list(APPEND PLUGIN_LIST "missed_events default") # This plugin will be loaded by default

install(
  TARGETS sched_events missed_events
  LIBRARY
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/plugins/"
)

set(PLUGINS ${PLUGIN_LIST} PARENT_SCOPE)
