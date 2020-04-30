// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

/*
 * rbd-nbd - RBD in userspace
 *
 * Copyright (C) 2015 - 2016 Kylin Corporation
 *
 * Author: Yunchuan Wen <yunchuan.wen@kylin-cloud.com>
 *         Li Wang <li.wang@kylin-cloud.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
*/

#include <linux/nbd.h>

#include "common/ceph_context.h"
#include "common/module.h"
#include "common/Thread.h"

#include "include/rbd/librbd.hpp"
#include "include/xlist.h"

class NBDServer
{
private:
  int fd;
  librbd::Image &image;
  std::string devpath;
  bool quiesce;
  std::string quiesce_hook;

public:
  NBDServer(int _fd, librbd::Image& _image, std::string _devpath, bool _quiesce,
            std::string _quiesce_hook)
    : fd(_fd)
    , image(_image)
    , devpath(_devpath)
    , quiesce(_quiesce)
    , quiesce_hook(_quiesce_hook)
    , reader_thread(*this, &NBDServer::reader_entry)
    , writer_thread(*this, &NBDServer::writer_entry)
    , quiesce_thread(*this, &NBDServer::quiesce_entry)
    , started(false)
  {
    std::vector<librbd::config_option_t> options;
    image.config_list(&options);
    for (auto &option : options) {
      if ((option.name == std::string("rbd_cache") ||
           option.name == std::string("rbd_cache_writethrough_until_flush")) &&
          option.value == "false") {
        allow_internal_flush = true;
        break;
      }
    }
  }

private:
  ceph::mutex disconnect_lock =
    ceph::make_mutex("NBDServer::DisconnectLocker");
  ceph::condition_variable disconnect_cond;
  std::atomic<bool> terminated = { false };
  std::atomic<bool> allow_internal_flush = { false };

  void shutdown();

  struct IOContext
  {
    xlist<IOContext*>::item item;
    NBDServer *server = nullptr;
    struct nbd_request request;
    struct nbd_reply reply;
    bufferlist data;
    int command = 0;

    IOContext()
      : item(this)
    {}
  };

  friend std::ostream &operator<<(std::ostream &os, const IOContext &ctx);

  ceph::mutex lock = ceph::make_mutex("NBDServer::Locker");
  ceph::condition_variable cond;
  xlist<IOContext*> io_pending;
  xlist<IOContext*> io_finished;

  void io_start(IOContext *ctx);
  void io_finish(IOContext *ctx);

  IOContext *wait_io_finish();
  void wait_clean();

  static void aio_callback(librbd::completion_t cb, void *arg);

  void reader_entry();
  void writer_entry();

  bool wait_quiesce();
  void wait_unquiesce();
  void wait_inflight_io();
  void quiesce_entry();

  void notify_quiesce();
  void notify_unquiesce();
  void run_quiesce_hook(const std::string &command);

  class ThreadHelper : public Thread
  {
  public:
    typedef void (NBDServer::*entry_func)();
  private:
    NBDServer &server;
    entry_func func;
  public:
    ThreadHelper(NBDServer &_server, entry_func _func)
      :server(_server)
      ,func(_func)
    {}
  protected:
    void* entry() override
    {
      (server.*func)();
      server.shutdown();
      return NULL;
    }
  } reader_thread, writer_thread, quiesce_thread;

  bool started;
  bool quiesced;
public:
  void start();
  void wait_for_disconnect();

  ~NBDServer();
};

std::ostream &operator<<(std::ostream &os, const NBDServer::IOContext &ctx);
