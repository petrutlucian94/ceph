#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rbd

#include "wvbd_handler.h"

#define _NTSCSI_USER_MODE_
#include <rpc.h>
#include <ddk/scsi.h>

#include "common/debug.h"
#include "common/errno.h"
#include "common/safe_io.h"
#include "common/SubProcess.h"
#include "common/Formatter.h"

#include "global/global_context.h"

WvbdHandler::~WvbdHandler()
{
  if (started && wvbd_device) {
    dout(10) << __func__ << ": terminating" << dendl;

    shutdown();

    WvbdClose(wvbd_device);

    started = false;
  }
}

int WvbdHandler::wait()
{
  int err = 0;
  if (started && wvbd_device) {
    dout(10) << __func__ << ": waiting" << dendl;

    err = WvbdWaitDispatcher(wvbd_device);
    if (err) {
      derr << __func__ << " failed waiting for dispatcher to stop: "
           << err << dendl;
    }
  }

  return err;
}

int WvbdAdminHook::call (std::string_view command, const cmdmap_t& cmdmap,
     Formatter *f,
     std::ostream& errss,
     bufferlist& out) {
    if (command == "wvbd stats") {
      return m_handler->dump_stats(f);
    }
    return -ENOSYS;
  }

int WvbdHandler::dump_stats(Formatter *f)
{
  if (!f) {
    return -EINVAL;
  }

  WVBD_USR_STATS stats = { 0 };
  DWORD buff_sz = sizeof(stats);
  DWORD err = WvbdGetUserspaceStats(
    wvbd_device, &stats, &buff_sz);
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

void WvbdHandler::shutdown()
{
  std::unique_lock l{shutdown_lock};
  if (!terminated && wvbd_device) {
    // We're requesting the device to be removed but continue serving IO
    // requests until the driver sends us the "Disconnect" event.
    WvbdRemove(wvbd_device);
    wait();
    terminated = true;
  }
}

void WvbdHandler::aio_callback(librbd::completion_t cb, void *arg)
{
  librbd::RBD::AioCompletion *aio_completion =
    reinterpret_cast<librbd::RBD::AioCompletion*>(cb);

  std::unique_ptr<WvbdHandler::IOContext> ctx{
    static_cast<WvbdHandler::IOContext*>(arg)};
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
  } else if ((ctx->req_type == WvbdReqTypeRead) &&
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

void WvbdHandler::send_io_response(WvbdHandler::IOContext *ctx) {
  WVBD_IO_RESPONSE wvbd_rsp = {0};
  wvbd_rsp.RequestHandle = ctx->req_handle;
  wvbd_rsp.RequestType = ctx->req_type;
  wvbd_rsp.Status = ctx->wvbd_status;

  ceph_assert(
    wvbd_device->Properties.MaxTransferLength >= ctx->data.length());

  WvbdSendResponse(
    ctx->handler->wvbd_device,
    &wvbd_rsp,
    ctx->data.c_str(),
    ctx->data.length());
}

void WvbdHandler::IOContext::set_sense(uint8_t sense_key, uint8_t asc, uint64_t info)
{
  WvbdSetSenseEx(&wvbd_status, sense_key, asc, info);
}

void WvbdHandler::IOContext::set_sense(uint8_t sense_key, uint8_t asc)
{
  WvbdSetSense(&wvbd_status, sense_key, asc);
}

void WvbdHandler::Read(
  PWVBD_DEVICE Device,
  UINT64 RequestHandle,
  PVOID Buffer,
  UINT64 BlockAddress,
  UINT32 BlockCount,
  BOOLEAN ForceUnitAccess)
{
  WvbdHandler* handler = (WvbdHandler*)Device->Context;

  UINT32 BlockSize = Device->Properties.BlockSize;

  WvbdHandler::IOContext* ctx = new WvbdHandler::IOContext();
  ctx->handler = handler;
  ctx->req_handle = RequestHandle;
  ctx->req_size = BlockCount * BlockSize;
  ctx->req_type = WvbdReqTypeRead;
  ctx->req_from = BlockAddress * BlockSize;

  ceph_assert(ctx->req_size <= RBD_WVBD_MAX_TRANSFER);
  dout(20) << *ctx << ": start" << dendl;

  librbd::RBD::AioCompletion *c = new librbd::RBD::AioCompletion(ctx, aio_callback);
  handler->image.aio_read(ctx->req_from, ctx->req_size, ctx->data, c);

  dout(20) << *ctx << ": submitted" << dendl;
}

void WvbdHandler::Write(
  PWVBD_DEVICE Device,
  UINT64 RequestHandle,
  PVOID Buffer,
  UINT64 BlockAddress,
  UINT32 BlockCount,
  BOOLEAN ForceUnitAccess)
{
  WvbdHandler* handler = (WvbdHandler*)Device->Context;

  UINT32 BlockSize = Device->Properties.BlockSize;

  WvbdHandler::IOContext* ctx = new WvbdHandler::IOContext();
  ctx->handler = handler;
  ctx->req_handle = RequestHandle;
  ctx->req_size = BlockCount * BlockSize;
  ctx->req_type = WvbdReqTypeWrite;
  ctx->req_from = BlockAddress * BlockSize;

  bufferptr ptr((char*)Buffer, ctx->req_size);
  ctx->data.push_back(ptr);

  dout(20) << *ctx << ": start" << dendl;

  librbd::RBD::AioCompletion *c = new librbd::RBD::AioCompletion(ctx, aio_callback);
  handler->image.aio_write(ctx->req_from, ctx->req_size, ctx->data, c);

  dout(20) << *ctx << ": submitted" << dendl;
}

void WvbdHandler::LogMessage(
    PWVBD_DEVICE Device,
    WvbdLogLevel LogLevel,
    const char* Message,
    const char* FileName,
    UINT32 Line,
    const char* FunctionName)
{
  // We're already passing the log level to WVBD, so we'll use the highest
  // log level here.
  dout(0) << "wvbd.dll!" << FunctionName << " "
          << WvbdLogLevelToStr(LogLevel) << " " << Message << dendl;
}


int WvbdHandler::start()
{
  int err = 0;
  WVBD_PROPERTIES wvbd_props = {0};

  instance_name.copy(wvbd_props.InstanceName, sizeof(wvbd_props.InstanceName));
  ceph_assert(strlen(RBD_WVBD_OWNER_NAME) < WVBD_MAX_OWNER_LENGTH);
  strncpy(wvbd_props.Owner, RBD_WVBD_OWNER_NAME, WVBD_MAX_OWNER_LENGTH);

  wvbd_props.BlockCount = block_count;
  wvbd_props.BlockSize = block_size;
  wvbd_props.MaxTransferLength = RBD_WVBD_MAX_TRANSFER;
  // TODO: flush/unmap
  wvbd_props.Flags.ReadOnly = readonly;
  wvbd_props.Flags.FlushSupported = 0;
  wvbd_props.Flags.UnmapSupported = 0;

  err = WvbdCreate(&wvbd_props, &RbdWvbdInterface, this,
                   wvbd_log_level, &wvbd_device);
  if (err)
    goto exit;

  started = true;

  err = WvbdStartDispatcher(wvbd_device, thread_count);
  if (err) {
      derr << "Could not start WVBD dispatcher. Error: " << err << dendl;
  }

exit:
  return err;
}

std::ostream &operator<<(std::ostream &os, const WvbdHandler::IOContext &ctx) {

  os << "[" << std::hex << ctx.req_handle;

  switch (ctx.req_type)
  {
  case WvbdReqTypeRead:
    os << " READ ";
    break;
  case WvbdReqTypeWrite:
    os << " WRITE ";
    break;
  case WvbdReqTypeFlush:
    os << " FLUSH ";
    break;
  case WvbdReqTypeUnmap:
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
