set(ceph_dokan_srcs
  ceph_dokan.cc
  posix_acl.cc
  dbg.cc
  utils.cc
  options.cc)
add_executable(ceph-dokan ${ceph_dokan_srcs})
target_link_libraries(ceph-dokan ${DOKAN_LIBRARIES}
  ${GSSAPI_LIBRARIES}
  client cephfs ceph-common global ${EXTRALIBS})
set_target_properties(ceph-dokan PROPERTIES
  COMPILE_FLAGS "-I${DOKAN_INCLUDE_DIRS}")
install(TARGETS ceph-dokan DESTINATION bin)
