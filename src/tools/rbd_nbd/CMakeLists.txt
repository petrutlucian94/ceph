add_executable(rbd-nbd rbd-nbd.cc)
target_link_libraries(rbd-nbd librbd librados global)
set_target_properties(rbd-nbd PROPERTIES COMPILE_FLAGS "-fpermissive")

if(LINUX)
    find_package(nl REQUIRED genl)
    target_link_libraries(rbd-nbd nl::genl)
endif(LINUX)

target_link_libraries(rbd-nbd setupapi)

install(TARGETS rbd-nbd DESTINATION bin)
