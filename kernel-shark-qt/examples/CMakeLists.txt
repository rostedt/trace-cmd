message("\n examples ...")

message(STATUS "dataload")
add_executable(dload          dataload.c)
target_link_libraries(dload   kshark)
