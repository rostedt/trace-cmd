message(STATUS "Building examples ...")

message(STATUS "Building dload")
add_executable(dload dataload.c)
target_link_libraries(dload kshark)

message(STATUS "Building dfilter")
add_executable(dfilter datafilter.c)
target_link_libraries(dfilter kshark)

message(STATUS "Building dhisto")
add_executable(dhisto datahisto.c)
target_link_libraries(dhisto kshark)

message(STATUS "Building confio")
add_executable(confio configio.c)
target_link_libraries(confio kshark)

message(STATUS "Building dplot")
add_executable(dplot dataplot.cpp)
target_link_libraries(dplot kshark-plot)

if(Qt5Widgets_FOUND)
  message(STATUS "Building widgetdemo")
  add_executable(widgetdemo widgetdemo.cpp)
  target_link_libraries(widgetdemo kshark-gui)

  message(STATUS "Building cmd_split")
  add_executable(cmd_split cmd_split.cpp)
  target_link_libraries(cmd_split kshark-gui)
endif(Qt5Widgets_FOUND)
