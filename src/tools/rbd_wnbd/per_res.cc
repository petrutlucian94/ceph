/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2022 Cloudbase Solutions
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rbd

#include "per_res.h"

#define _NTSCSI_USER_MODE_
#include <rpc.h>
#include <ddk/scsi.h>

#include <boost/endian/conversion.hpp>

#include "common/debug.h"
#include "common/errno.h"

#include "global/global_context.h"

// We'll try to stay compatible with the "target_core_rbd" module
#define RBD_PR_INFO_XATTR_KEY      "pr_info.win32"
#define RBD_PR_INFO_XATTR_MAX_SIZE 8192

#define RBD_HEADER_PREFIX "rbd_header."
#define RBD_SUFFIX        ".rbd"

std::string RbdPrInfo::get_header_obj_name()
{
  // TODO: double check this
  std::string image_id;
  auto r = image.get_id(&image_id);
  if (r < 0) {
    // old format
    std::string image_name;
    r = image.get_name(&image_name);
    // should always return 0
    ceph_assert(!r);
    return image_name + RBD_SUFFIX;
  } else {
    return RBD_HEADER_PREFIX + image_id;
  }
}

int RbdPrInfo::retrieve()
{
  bufferlist bl;
  auto object_name = get_header_obj_name();
  auto r = rados_ctx.getxattr(object_name, RBD_PR_INFO_XATTR_KEY, bl);
  if (r < 0) {
    return r;
  }

  bufferlist::const_iterator ci = bl.begin();
  decode(ci);
  return 0;
}

int RbdPrInfo::retrieve_or_create()
{
  auto r = retrieve();
  if (r == -ENODATA) {
    r = create();
  }
  return r;
}

int RbdPrInfo::create()
{
  bufferlist bl;
  encode(bl);

  auto object_name = get_header_obj_name();
  auto r = rados_ctx.setxattr(object_name, RBD_PR_INFO_XATTR_KEY, bl);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RbdPrInfo::replace()
{
  bufferlist bl;
  encode(bl);

  librados::ObjectWriteOperation o;
  o.cmpxattr(RBD_PR_INFO_XATTR_KEY, CEPH_OSD_CMPXATTR_OP_EQ, bl);

  auto object_name = get_header_obj_name();
  auto r = rados_ctx.operate(object_name, &o);
  if (r < 0) {
    return r;
  }

  return 0;
}

int WnbdPerResInOperation::read_keys()
{
  auto pr_info = RbdPrInfo(rados_ctx, image);
  int r = pr_info.retrieve_or_create();
  if (r < 0) {
    return r;
  }

  uint32_t generation_be = boost::endian::native_to_big(pr_info.generation);
  out_buff.append(
    reinterpret_cast<const char*>(&generation_be), sizeof(generation_be));

  uint32_t allocation_length_be = boost::endian::native_to_big(
    uint32_t(pr_info.keys.size()));
  out_buff.append(
    reinterpret_cast<const char*>(&allocation_length_be), sizeof(allocation_length_be));

  for (auto key : pr_info.keys) {
    auto key_be = boost::endian::native_to_big(key);
    out_buff.append(
      reinterpret_cast<const char*>(&key_be), sizeof(key_be));
  }

  return 0;
}

int WnbdPerResInOperation::read_reservations()
{
  // TODO: Placeholder
  return -ENOTSUP;
}

// TODO: set sense status
int WnbdPerResInOperation::start()
{
  switch (service_action) {
  case RESERVATION_ACTION_READ_KEYS:
    return read_keys();
  case RESERVATION_ACTION_READ_RESERVATIONS:
    return read_reservations();
  default:
    return -ENOTSUP;
  }
  return 0;
}

// TODO: set sense status
int WnbdPerResOutOperation::register_key()
{
  if (in_buff.length() < sizeof(PRO_PARAMETER_LIST)) {
    return -EOVERFLOW;
  }

  PPRO_PARAMETER_LIST params = (PPRO_PARAMETER_LIST) in_buff.c_str();

  uint64_t res_key = boost::endian::big_to_native(
    *reinterpret_cast<uint64_t*>(params->ReservationKey));
  uint64_t sv_act_res_key = boost::endian::big_to_native(
    *reinterpret_cast<uint64_t*>(params->ServiceActionReservationKey));
  uint32_t scope_specif_addr = boost::endian::big_to_native(
    *reinterpret_cast<uint64_t*>(params->ScopeSpecificAddress));

  // TODO: Placeholder
  return -ENOTSUP;
}

// TODO: set sense status
int WnbdPerResOutOperation::start()
{
  switch (service_action) {
  case RESERVATION_ACTION_REGISTER:
    return register_key();
  default:
    return -ENOTSUP;
  }
  return 0;
}
