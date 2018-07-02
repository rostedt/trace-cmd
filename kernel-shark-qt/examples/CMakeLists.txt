message("\n examples ...")

message(STATUS "dataload")
add_executable(dload          dataload.c)
target_link_libraries(dload   kshark)

message(STATUS "datafilter")
add_executable(dfilter          datafilter.c)
target_link_libraries(dfilter   kshark)
