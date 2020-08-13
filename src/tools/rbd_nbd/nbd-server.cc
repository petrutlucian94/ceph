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

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rbd

#include "nbd-server.h"

#include "common/debug.h"
#include "common/errno.h"
#include "common/safe_io.h"
#include "common/SubProcess.h"
#include "common/Formatter.h"

#include "global/global_context.h"

#ifdef CEPH_BIG_ENDIAN
#define ntohll(a) (a)
#elif defined(CEPH_LITTLE_ENDIAN)
#define ntohll(a) swab(a)
#else
#error "Could not determine endianess"
#endif
#define htonll(a) ntohll(a)

int NbdServerHook::call (std::string_view command, const cmdmap_t& cmdmap,
     Formatter *f,
     std::ostream& errss,
     bufferlist& out) {
    if (command == "nbd stats") {
      return m_server->dump_stats(f);
    }
    return -ENOSYS;
  }

int NBDServer::dump_stats(Formatter *f)
{
  if(!f) {
    return -EINVAL;
  }

  std::lock_guard l{stats_lock};
  f->open_object_section("stats");
  f->dump_int("TotalReceivedIORequests", stats.TotalReceivedIORequests);
  f->dump_int("TotalSubmittedIORequests", stats.TotalSubmittedIORequests);
  f->dump_int("TotalReceivedIOReplies", stats.TotalReceivedIOReplies);
  f->dump_int("UnsubmittedIORequests", stats.UnsubmittedIORequests);
  f->dump_int("PendingSubmittedIORequests", stats.PendingSubmittedIORequests);
  f->dump_int("AbortedSubmittedIORequests", stats.AbortedSubmittedIORequests);
  f->dump_int("AbortedUnsubmittedIORequests", stats.AbortedUnsubmittedIORequests);
  f->dump_int("CompletedAbortedIORequests", stats.CompletedAbortedIORequests);
  f->close_section();

  return 0;
}

void NBDServer::run_quiesce_hook(const std::string &command) {
  dout(10) << __func__ << ": " << quiesce_hook << " " << devpath << " "
           << command << dendl;

  SubProcess hook(quiesce_hook.c_str(), SubProcess::CLOSE, SubProcess::PIPE,
                  SubProcess::PIPE);
  hook.add_cmd_args(devpath.c_str(), command.c_str(), NULL);
  bufferlist err;
  int r = hook.spawn();
  if (r != 0) {
    err.append("subprocess spawn failed");
  } else {
    err.read_fd(hook.get_stderr(), 16384);
    r = hook.join();
  }
  if (r != 0) {
    derr << __func__ << ": " << quiesce_hook << " " << devpath << " "
         << command << " failed: " << err.to_str() << dendl;
  } else {
    dout(10) << " succeeded: " << err.to_str() << dendl;
  }
}

void NBDServer::shutdown()
{
  bool expected = false;
  if (terminated.compare_exchange_strong(expected, true)) {
    ::shutdown(fd, SHUT_RDWR);

    std::lock_guard l{lock};
    cond.notify_all();
  }
}

void NBDServer::io_start(NBDServer::IOContext *ctx)
{
  std::lock_guard l{lock};
  io_pending.push_back(&ctx->item);
}

void NBDServer::io_finish(NBDServer::IOContext *ctx)
{
  std::lock_guard l{lock};
  ceph_assert(ctx->item.is_on_list());
  ctx->item.remove_myself();
  io_finished.push_back(&ctx->item);
  cond.notify_all();
}

NBDServer::IOContext *NBDServer::wait_io_finish()
{
  std::unique_lock l{lock};
  cond.wait(l, [this] { return !io_finished.empty() || terminated; });

  if (io_finished.empty())
    return NULL;

  NBDServer::IOContext *ret = io_finished.front();
  io_finished.pop_front();

  return ret;
}

void NBDServer::wait_clean()
{
  ceph_assert(!reader_thread.is_started());
  std::unique_lock l{lock};
  cond.wait(l, [this] { return io_pending.empty(); });

  while(!io_finished.empty()) {
    std::unique_ptr<NBDServer::IOContext> free_ctx(io_finished.front());
    io_finished.pop_front();
  }
}

void NBDServer::aio_callback(librbd::completion_t cb, void *arg)
{
  librbd::RBD::AioCompletion *aio_completion =
  reinterpret_cast<librbd::RBD::AioCompletion*>(cb);

  NBDServer::IOContext *ctx = reinterpret_cast<NBDServer::IOContext *>(arg);
  int ret = aio_completion->get_return_value();

  dout(20) << __func__ << ": " << *ctx << dendl;

  if (ret == -EINVAL) {
    // if shrinking an image, a pagecache writeback might reference
    // extents outside of the range of the new image extents
    dout(0) << __func__ << ": masking IO out-of-bounds error" << dendl;
    ctx->data.clear();
    ret = 0;
  }

  if (ret < 0) {
    ctx->reply.error = htonl(-ret);
  } else if ((ctx->command == NBD_CMD_READ) &&
              ret < static_cast<int>(ctx->request.len)) {
    int pad_byte_count = static_cast<int> (ctx->request.len) - ret;
    ctx->data.append_zero(pad_byte_count);
    dout(20) << __func__ << ": " << *ctx << ": Pad byte count: "
             << pad_byte_count << dendl;
    ctx->reply.error = htonl(0);
  } else {
    ctx->reply.error = htonl(0);
  }
  ctx->server->io_finish(ctx);

  aio_completion->release();
}

void NBDServer::reader_entry()
{
  while (!terminated) {
    std::unique_ptr<NBDServer::IOContext> ctx(new NBDServer::IOContext());
    ctx->server = this;

    dout(20) << __func__ << ": waiting for nbd request" << dendl;

    int r = safe_recv_exact(fd, &ctx->request, sizeof(struct nbd_request));
    if (r < 0) {
      derr << "failed to read nbd request header: " << cpp_strerror(r)
           << dendl;
      goto signal;
    }

    if (ctx->request.magic != htonl(NBD_REQUEST_MAGIC)) {
      derr << "invalid nbd request header" << dendl;
      goto signal;
    }

    ctx->request.from = ntohll(ctx->request.from);
    ctx->request.type = ntohl(ctx->request.type);
    ctx->request.len = ntohl(ctx->request.len);

    ctx->reply.magic = htonl(NBD_REPLY_MAGIC);
    memcpy(ctx->reply.handle, ctx->request.handle, sizeof(ctx->reply.handle));

    ctx->command = ctx->request.type & 0x0000ffff;

    dout(20) << *ctx << ": start" << dendl;

    if(ctx->command != NBD_CMD_DISC) {
      stats.TotalReceivedIORequests += 1;
      stats.UnsubmittedIORequests += 1;
    }

    switch (ctx->command)
    {
      case NBD_CMD_DISC:
        // NBD_DO_IT will return when pipe is closed
        dout(0) << "disconnect request received" << dendl;
        goto signal;
      case NBD_CMD_WRITE:
        bufferptr ptr(ctx->request.len);
        r = safe_recv_exact(fd, ptr.c_str(), ctx->request.len);
        if (r < 0) {
          derr << *ctx << ": failed to read nbd request data: "
               << cpp_strerror(r) << dendl;
          goto signal;
        }
        ctx->data.push_back(ptr);
        break;
    }

    NBDServer::IOContext *pctx = ctx.release();
    io_start(pctx);
    librbd::RBD::AioCompletion *c = new librbd::RBD::AioCompletion(pctx, aio_callback);
    int op_flags = 0;
    switch (pctx->command)
    {
      case NBD_CMD_WRITE:
        if (pctx->request.type & NBD_CMD_FLAG_FUA) {
          op_flags |= LIBRADOS_OP_FLAG_FADVISE_FUA;
        }
        image.aio_write2(pctx->request.from, pctx->request.len, pctx->data, c,
                         op_flags);
        break;
      case NBD_CMD_READ:
        image.aio_read(pctx->request.from, pctx->request.len, pctx->data, c);
        break;
      case NBD_CMD_FLUSH:
        image.aio_flush(c);
        allow_internal_flush = true;
        break;
      case NBD_CMD_TRIM:
        image.aio_discard(pctx->request.from, pctx->request.len, c);
        break;
      default:
        derr << *pctx << ": invalid request command" << dendl;
        c->release();
        goto signal;
    }
    {
      std::lock_guard l{stats_lock};

      stats.TotalSubmittedIORequests += 1;
      stats.UnsubmittedIORequests -= 1;
      stats.PendingSubmittedIORequests += 1;
    }
  }
  dout(20) << __func__ << ": terminated" << dendl;

signal:
  std::lock_guard l{disconnect_lock};
  disconnect_cond.notify_all();
}

void NBDServer::writer_entry()
{
  while (!terminated) {
    dout(20) << __func__ << ": waiting for io request" << dendl;
    std::unique_ptr<NBDServer::IOContext> ctx(wait_io_finish());
    if (!ctx) {
      dout(20) << __func__ << ": no io requests, terminating" << dendl;
      return;
    }

    dout(20) << __func__ << ": got: " << *ctx << dendl;

    stats.TotalReceivedIOReplies += 1;

    int r = safe_send(fd, &ctx->reply, sizeof(struct nbd_reply));

    {
      std::lock_guard l{stats_lock};
      stats.PendingSubmittedIORequests -= 1;
    }

    if (r < 0) {
      derr << *ctx << ": failed to write reply header: " << cpp_strerror(r)
           << dendl;
      return;
    }
    if (ctx->command == NBD_CMD_READ && ctx->reply.error == htonl(0)) {
      r = ctx->data.send_fd(fd);
      if (r < 0) {
        derr << *ctx << ": failed to write replay data: " << cpp_strerror(r)
             << dendl;
        return;
      }
    }
    dout(20) << *ctx << ": finish" << dendl;
  }
  dout(20) << __func__ << ": terminated" << dendl;
}

bool NBDServer::wait_quiesce() {
    dout(20) << __func__ << dendl;

    std::unique_lock locker{lock};
    cond.wait(locker, [this] { return quiesce || terminated; });

    if (terminated) {
      return false;
    }

    dout(20) << __func__ << ": got quiesce request" << dendl;
    return true;
  }

void NBDServer::wait_unquiesce() {
  dout(20) << __func__ << dendl;

  std::unique_lock locker{lock};
  cond.wait(locker, [this] { return !quiesce || terminated; });

  dout(20) << __func__ << ": got unquiesce request" << dendl;
}

void NBDServer::wait_inflight_io() {
  if (!allow_internal_flush) {
      return;
  }

  uint64_t features = 0;
  image.features(&features);
  if ((features & RBD_FEATURE_EXCLUSIVE_LOCK) != 0) {
    bool is_owner = false;
    image.is_exclusive_lock_owner(&is_owner);
    if (!is_owner) {
      return;
    }
  }

  dout(20) << __func__ << dendl;

  int r = image.flush();
  if (r < 0) {
    derr << "flush failed: " << cpp_strerror(r) << dendl;
  }
}

void NBDServer::quiesce_entry()
{
  ceph_assert(quiesce);

  while (wait_quiesce()) {

    run_quiesce_hook("quiesce");

    wait_inflight_io();

    image.quiesce_complete(0); // TODO: return quiesce hook exit code

    wait_unquiesce();

    run_quiesce_hook("unquiesce");
  }
}

void NBDServer::start()
{
  if (!started) {
    dout(10) << __func__ << ": starting" << dendl;

    started = true;

    reader_thread.create("rbd_reader");
    writer_thread.create("rbd_writer");
    if (quiesce) {
      quiesce_thread.create("rbd_quiesce");
    }
  }
}

void NBDServer::wait_for_disconnect()
{
  if (!started)
    return;

  std::unique_lock l{disconnect_lock};
  disconnect_cond.wait(l);
}

void NBDServer::notify_quiesce() {
  dout(10) << __func__ << dendl;

  ceph_assert(quiesce);

  std::unique_lock locker{lock};
  ceph_assert(quiesced == false);
  quiesced = true;
  cond.notify_all();
}

void NBDServer::notify_unquiesce() {
  dout(10) << __func__ << dendl;

  ceph_assert(quiesce);

  std::unique_lock locker{lock};
  ceph_assert(quiesced == true);
  quiesced = false;
  cond.notify_all();
}

NBDServer::~NBDServer()
{
  if (started) {
    dout(10) << __func__ << ": terminating" << dendl;

    shutdown();

    reader_thread.join();
    writer_thread.join();
    if (quiesce) {
      quiesce_thread.join();
    }

    wait_clean();

    started = false;
  }
}

std::ostream &operator<<(std::ostream &os, const NBDServer::IOContext &ctx) {

  os << "[" << std::hex << ntohll(*((uint64_t *)ctx.request.handle));

  switch (ctx.command)
  {
  case NBD_CMD_WRITE:
    os << " WRITE ";
    break;
  case NBD_CMD_READ:
    os << " READ ";
    break;
  case NBD_CMD_FLUSH:
    os << " FLUSH ";
    break;
  case NBD_CMD_TRIM:
    os << " TRIM ";
    break;
  default:
    os << " UNKNOWN(" << ctx.command << ") ";
    break;
  }

  os << ctx.request.from << "~" << ctx.request.len << " "
     << std::dec << ntohl(ctx.reply.error) << "]";

  return os;
}
