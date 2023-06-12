/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2023 Cloudbase Solutions
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#pragma once

#include "rbd_mapping_config.h"
#include "wnbd_handler.h"

class WNBDWatchCtx : public librbd::UpdateWatchCtx
{
private:
  librados::IoCtx &io_ctx;
  WnbdHandler* handler;
  librbd::Image &image;
  uint64_t size;
public:
  WNBDWatchCtx(librados::IoCtx& io_ctx, WnbdHandler* handler,
               librbd::Image& image, uint64_t size)
    : io_ctx(io_ctx)
    , handler(handler)
    , image(image)
    , size(size)
  {
  }

  ~WNBDWatchCtx() override {}

  void handle_notify() override
  {
    uint64_t new_size;

    if (image.size(&new_size) == 0 && new_size != size &&
        handler->resize(new_size) == 0) {
      size = new_size;
    }
  }
};

typedef std::function<void(std::string devpath, int ret)> disconnect_cbk_t;

class RbdMapping
{
private:
  Config cfg;
  // We're sharing the rados object across mappings in order to
  // reuse the OSD connections.
  librados::Rados& rados;

  librbd::RBD rbd;
  librados::IoCtx io_ctx;
  librbd::Image image;
  uint64_t initial_image_size;

  WnbdHandler* handler = nullptr;
  uint64_t watch_handle;
  WNBDWatchCtx* watch_ctx = nullptr;
  disconnect_cbk_t disconnect_cbk;

  ceph::mutex shutdown_lock = ceph::make_mutex("RbdMapping::ShutdownLock");
  std::thread monitor_thread;

  int init();

public:
  RbdMapping(Config& _cfg,
             librados::Rados& _rados)
    : cfg(_cfg)
    , rados(_rados)
  {}

  RbdMapping(Config& _cfg,
             librados::Rados& _rados,
             disconnect_cbk_t _disconnect_cbk)
    : cfg(_cfg)
    , rados(_rados)
    , disconnect_cbk(_disconnect_cbk)
  {}

  ~RbdMapping();

  int start();
  int wait();
  int shutdown();
};

class RbdMappingDispatcher
{
private:
  librados::Rados& rados;

  std::map<std::string, std::unique_ptr<RbdMapping>> mappings;
  ceph::mutex map_mutex = ceph::make_mutex("RbdMappingDispatcher::MapMutex");

  void disconnect_cbk(std::string devpath, int ret);

public:
  RbdMappingDispatcher(librados::Rados& _rados)
    : rados(_rados)
  {}

  int create(Config& cfg);
};
