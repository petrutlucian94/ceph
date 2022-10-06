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

#ifndef WNBD_PER_RES_H
#define WNBD_PER_RES_H

#include <wnbd.h>

#include "include/encoding.h"
#include "include/rbd/librbd.hpp"

struct per_reg {
  uint64_t key;

  void encode(bufferlist &bl)
  {
    using ceph::encode;
    ENCODE_START(1, 1, bl);
    encode(key, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::const_iterator &bl)
  {
    using ceph::decode;
    DECODE_START(1, bl);
    decode(key, bl);
    DECODE_FINISH(bl);
  }
};
WRITE_CLASS_ENCODER(per_reg)

class RbdPrInfo
{
private:
  librados::IoCtx &rados_ctx;
  librbd::Image &image;

  // The last retrieved xattr state, used for "compare and write"
  // operations.
  bufferlist last_bl;

  std::string get_header_obj_name();
public:
  // TODO: consider endianness
  uint32_t generation;
  std::vector<per_reg> regs;

  void encode(bufferlist &bl)
  {
    using ceph::encode;
    ENCODE_START(1, 1, bl);
    encode(generation, bl);
    encode(regs, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::const_iterator &bl)
  {
    using ceph::decode;
    DECODE_START(1, bl);
    decode(generation, bl);
    decode(regs, bl);
    DECODE_FINISH(bl);
  }

  int create();
  int retrieve();
  int retrieve_or_create();
  // Performs an atomic "compare and write" operation, checking the last known
  // state of the xattr data, which must be explicitly retrieved first.
  int safe_replace();

  friend std::ostream &operator<<(std::ostream &os, const RbdPrInfo &pr_info);

  RbdPrInfo(librbd::IoCtx& _rados_ctx,
            librbd::Image& _image)
    : rados_ctx(_rados_ctx)
    , image(_image)
    , generation(0)
  {
  }
};

std::ostream &operator<<(std::ostream &os, const RbdPrInfo &pr_info);

// WNBD PERSISTENT RESERVATION IN operation
class WnbdPerResInOperation
{
private:
  librados::IoCtx &rados_ctx;
  librbd::Image &image;
  uint8_t service_action;

  bufferlist& out_buff;
  PWNBD_STATUS wnbd_status;

  int read_keys();
  int read_reservations();

public:
  WnbdPerResInOperation(librbd::IoCtx& _rados_ctx,
                        librbd::Image& _image,
                        uint16_t _service_action,
                        bufferlist& _out_buff,
                        PWNBD_STATUS _wnbd_status)
    : rados_ctx(_rados_ctx)
    , image(_image)
    , service_action(_service_action)
    , out_buff(_out_buff)
    , wnbd_status(_wnbd_status)
  {
  }

  int execute();
};

// WNBD PERSISTENT RESERVATION OUT operation
class WnbdPerResOutOperation
{
private:
  librados::IoCtx &rados_ctx;
  librbd::Image &image;
  uint8_t service_action;
  uint8_t scope;
  uint8_t type;

  bufferlist& in_buff;
  PWNBD_STATUS wnbd_status;

  int register_key();

public:
  WnbdPerResOutOperation(librbd::IoCtx& _rados_ctx,
                        librbd::Image& _image,
                        uint8_t _service_action,
                        uint8_t _scope,
                        uint8_t _type,
                        bufferlist& _in_buff,
                        PWNBD_STATUS _wnbd_status)
    : rados_ctx(_rados_ctx)
    , image(_image)
    , service_action(_service_action)
    , scope(_scope)
    , type(_type)
    , in_buff(_in_buff)
    , wnbd_status(_wnbd_status)
  {
  }

  int execute();
};


#endif // WNBD_PER_RES_H
