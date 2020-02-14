add_executable(rbd-nbd rbd-nbd.cc)
target_link_libraries(rbd-nbd librbd librados global)

if(LINUX)
    find_package(nl REQUIRED genl)
    target_link_libraries(rbd-nbd nl::genl)
endif(LINUX)

install(TARGETS rbd-nbd DESTINATION bin)
