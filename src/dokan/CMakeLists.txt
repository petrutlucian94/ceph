set(ceph_dokan_srcs
  ceph_dokan.c
  posix_acl.cc
  dbg.c
  utils.c)
add_executable(ceph-dokan ${ceph_dokan_srcs})
target_link_libraries(ceph-dokan ${DOKAN_LIBRARIES}
  ${GSSAPI_LIBRARIES} client cephfs ceph-common global-static ${EXTRALIBS})
set_target_properties(ceph-dokan PROPERTIES
  COMPILE_FLAGS "-I${DOKAN_INCLUDE_DIRS}")
install(TARGETS ceph-dokan DESTINATION bin)
