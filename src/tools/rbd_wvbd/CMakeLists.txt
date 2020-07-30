add_executable(rbd-wvbd wvbd_handler.cc rbd_wvbd.cc)
set_target_properties(
    rbd-wvbd PROPERTIES COMPILE_FLAGS
    "-fpermissive -I${WVBD_INCLUDE_DIRS}")
target_link_libraries(
    rbd-wvbd setupapi rpcrt4
    ${WVBD_LIBRARIES}
    ${Boost_FILESYSTEM_LIBRARY}
    librbd librados global)
install(TARGETS rbd-wvbd DESTINATION bin)
