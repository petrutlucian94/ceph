#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rbd

#include "wnbd_handler.h"

#define _NTSCSI_USER_MODE_
#include <rpc.h>
#include <ddk/scsi.h>

#include "common/debug.h"
#include "common/errno.h"
#include "common/safe_io.h"
#include "common/SubProcess.h"
#include "common/Formatter.h"

#include "global/global_context.h"

WnbdHandler::~WnbdHandler()
{
  if (started && wnbd_device) {
    dout(10) << __func__ << ": terminating" << dendl;

    shutdown();

    WnbdClose(wnbd_device);

    started = false;
  }
}

int WnbdHandler::wait()
{
  int err = 0;
  if (started && wnbd_device) {
    dout(10) << __func__ << ": waiting" << dendl;

    err = WnbdWaitDispatcher(wnbd_device);
    if (err) {
      derr << __func__ << " failed waiting for dispatcher to stop: "
           << err << dendl;
    }
  }

  return err;
}

int WnbdAdminHook::call (std::string_view command, const cmdmap_t& cmdmap,
     Formatter *f,
     std::ostream& errss,
     bufferlist& out) {
    if (command == "wnbd stats") {
      return m_handler->dump_stats(f);
    }
    return -ENOSYS;
  }

int WnbdHandler::dump_stats(Formatter *f)
{
  if (!f) {
    return -EINVAL;
  }

  WNBD_USR_STATS stats = { 0 };
  DWORD buff_sz = sizeof(stats);
  DWORD err = WnbdGetUserspaceStats(
    wnbd_device, &stats, &buff_sz);
  if (err) {
    derr << "Failed to retrieve WNBD userspace stats. Error: " << err << dendl;
    return -EINVAL;
  }

  f->open_object_section("stats");
  f->dump_int("TotalReceivedRequests", stats.TotalReceivedRequests);
  f->dump_int("TotalSubmittedRequests", stats.TotalSubmittedRequests);
  f->dump_int("TotalReceivedReplies", stats.TotalReceivedReplies);
  f->dump_int("UnsubmittedRequests", stats.UnsubmittedRequests);
  f->dump_int("PendingSubmittedRequests", stats.PendingSubmittedRequests);
  f->dump_int("ReadErrors", stats.ReadErrors);
  f->dump_int("WriteErrors", stats.WriteErrors);
  f->dump_int("FlushErrors", stats.FlushErrors);
  f->dump_int("UnmapErrors", stats.UnmapErrors);
  f->dump_int("InvalidRequests", stats.InvalidRequests);
  f->dump_float("TotalRWRequests", stats.TotalRWRequests);
  f->dump_int("TotalReadBlocks", stats.TotalReadBlocks);
  f->dump_int("TotalWrittenBlocks", stats.TotalWrittenBlocks);

  f->close_section();
  return 0;
}

void WnbdHandler::shutdown()
{
  std::unique_lock l{shutdown_lock};
  if (!terminated && wnbd_device) {
    // We're requesting the device to be removed but continue serving IO
    // requests until the driver sends us the "Disconnect" event.
    WnbdRemove(wnbd_device, FALSE);
    wait();
    terminated = true;
  }
}

void WnbdHandler::aio_callback(librbd::completion_t cb, void *arg)
{
  librbd::RBD::AioCompletion *aio_completion =
    reinterpret_cast<librbd::RBD::AioCompletion*>(cb);

  std::unique_ptr<WnbdHandler::IOContext> ctx{
    static_cast<WnbdHandler::IOContext*>(arg)};
  int ret = aio_completion->get_return_value();

  dout(20) << __func__ << ": " << *ctx << dendl;

  if (ret == -EINVAL) {
    // if shrinking an image, a pagecache writeback might reference
    // extents outside of the range of the new image extents
    dout(0) << __func__ << ": masking IO out-of-bounds error" << *ctx << dendl;
    ctx->data.clear();
    ret = 0;
  }

  if (ret < 0) {
    ctx->err_code = -ret;
    // TODO: check the actual error.
    ctx->set_sense(SCSI_SENSE_MEDIUM_ERROR,
                   SCSI_ADSENSE_UNRECOVERED_ERROR);
  } else if ((ctx->req_type == WnbdReqTypeRead) &&
              ret < static_cast<int>(ctx->req_size)) {
    int pad_byte_count = static_cast<int> (ctx->req_size) - ret;
    ctx->data.append_zero(pad_byte_count);
    dout(20) << __func__ << ": " << *ctx << ": Pad byte count: "
             << pad_byte_count << dendl;
    ctx->err_code = 0;
  } else {
    ctx->err_code = 0;
  }

  ctx->handler->send_io_response(ctx.get());

  aio_completion->release();
}

void WnbdHandler::send_io_response(WnbdHandler::IOContext *ctx) {
  WNBD_IO_RESPONSE wnbd_rsp = {0};
  wnbd_rsp.RequestHandle = ctx->req_handle;
  wnbd_rsp.RequestType = ctx->req_type;
  wnbd_rsp.Status = ctx->wnbd_status;

  ceph_assert(
    wnbd_device->Properties.MaxTransferLength >= ctx->data.length());

  WnbdSendResponse(
    ctx->handler->wnbd_device,
    &wnbd_rsp,
    ctx->data.c_str(),
    ctx->data.length());
}

void WnbdHandler::IOContext::set_sense(uint8_t sense_key, uint8_t asc, uint64_t info)
{
  WnbdSetSenseEx(&wnbd_status, sense_key, asc, info);
}

void WnbdHandler::IOContext::set_sense(uint8_t sense_key, uint8_t asc)
{
  WnbdSetSense(&wnbd_status, sense_key, asc);
}

void WnbdHandler::Read(
  PWNBD_DEVICE Device,
  UINT64 RequestHandle,
  PVOID Buffer,
  UINT64 BlockAddress,
  UINT32 BlockCount,
  BOOLEAN ForceUnitAccess)
{
  WnbdHandler* handler = (WnbdHandler*)Device->Context;

  UINT32 BlockSize = Device->Properties.BlockSize;

  WnbdHandler::IOContext* ctx = new WnbdHandler::IOContext();
  ctx->handler = handler;
  ctx->req_handle = RequestHandle;
  ctx->req_size = BlockCount * BlockSize;
  ctx->req_type = WnbdReqTypeRead;
  ctx->req_from = BlockAddress * BlockSize;

  ceph_assert(ctx->req_size <= RBD_WNBD_MAX_TRANSFER);
  dout(20) << *ctx << ": start" << dendl;

  librbd::RBD::AioCompletion *c = new librbd::RBD::AioCompletion(ctx, aio_callback);
  handler->image.aio_read(ctx->req_from, ctx->req_size, ctx->data, c);

  dout(20) << *ctx << ": submitted" << dendl;
}

void WnbdHandler::Write(
  PWNBD_DEVICE Device,
  UINT64 RequestHandle,
  PVOID Buffer,
  UINT64 BlockAddress,
  UINT32 BlockCount,
  BOOLEAN ForceUnitAccess)
{
  WnbdHandler* handler = (WnbdHandler*)Device->Context;

  UINT32 BlockSize = Device->Properties.BlockSize;

  WnbdHandler::IOContext* ctx = new WnbdHandler::IOContext();
  ctx->handler = handler;
  ctx->req_handle = RequestHandle;
  ctx->req_size = BlockCount * BlockSize;
  ctx->req_type = WnbdReqTypeWrite;
  ctx->req_from = BlockAddress * BlockSize;

  bufferptr ptr((char*)Buffer, ctx->req_size);
  ctx->data.push_back(ptr);

  dout(20) << *ctx << ": start" << dendl;

  librbd::RBD::AioCompletion *c = new librbd::RBD::AioCompletion(ctx, aio_callback);
  handler->image.aio_write(ctx->req_from, ctx->req_size, ctx->data, c);

  dout(20) << *ctx << ": submitted" << dendl;
}

void WnbdHandler::LogMessage(
    PWNBD_DEVICE Device,
    WnbdLogLevel LogLevel,
    const char* Message,
    const char* FileName,
    UINT32 Line,
    const char* FunctionName)
{
  // We're already passing the log level to WNBD, so we'll use the highest
  // log level here.
  dout(0) << "wnbd.dll!" << FunctionName << " "
          << WnbdLogLevelToStr(LogLevel) << " " << Message << dendl;
}


int WnbdHandler::start()
{
  int err = 0;
  WNBD_PROPERTIES wnbd_props = {0};

  instance_name.copy(wnbd_props.InstanceName, sizeof(wnbd_props.InstanceName));
  ceph_assert(strlen(RBD_WNBD_OWNER_NAME) < WNBD_MAX_OWNER_LENGTH);
  strncpy(wnbd_props.Owner, RBD_WNBD_OWNER_NAME, WNBD_MAX_OWNER_LENGTH);

  wnbd_props.BlockCount = block_count;
  wnbd_props.BlockSize = block_size;
  wnbd_props.MaxTransferLength = RBD_WNBD_MAX_TRANSFER;
  // TODO: flush/unmap
  wnbd_props.Flags.ReadOnly = readonly;
  wnbd_props.Flags.FlushSupported = 0;
  wnbd_props.Flags.UnmapSupported = 0;

  err = WnbdCreate(&wnbd_props, &RbdWnbdInterface, this,
                   wnbd_log_level, &wnbd_device);
  if (err)
    goto exit;

  started = true;

  err = WnbdStartDispatcher(wnbd_device, thread_count);
  if (err) {
      derr << "Could not start WNBD dispatcher. Error: " << err << dendl;
  }

exit:
  return err;
}

std::ostream &operator<<(std::ostream &os, const WnbdHandler::IOContext &ctx) {

  os << "[" << std::hex << ctx.req_handle;

  switch (ctx.req_type)
  {
  case WnbdReqTypeRead:
    os << " READ ";
    break;
  case WnbdReqTypeWrite:
    os << " WRITE ";
    break;
  case WnbdReqTypeFlush:
    os << " FLUSH ";
    break;
  case WnbdReqTypeUnmap:
    os << " TRIM ";
    break;
  default:
    os << " UNKNOWN(" << ctx.req_type << ") ";
    break;
  }

  os << ctx.req_from << "~" << ctx.req_size << " "
     << std::dec << ntohl(ctx.err_code) << "]";

  return os;
}
