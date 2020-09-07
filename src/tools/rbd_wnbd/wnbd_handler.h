#ifndef WNBD_HANDLER_H
#define WNBD_HANDLER_H

#include <wnbd.h>

#include "common/admin_socket.h"
#include "common/ceph_context.h"
#include "common/Thread.h"

#include "include/rbd/librbd.hpp"
#include "include/xlist.h"

#include "global/global_context.h"

// TODO: make this configurable.
#define RBD_WNBD_MAX_TRANSFER 2 * 1024 * 1024

// Not defined by mingw.
#ifndef SCSI_ADSENSE_UNRECOVERED_ERROR
#define SCSI_ADSENSE_UNRECOVERED_ERROR 0x11
#endif

// The following will be assigned to the "Owner" field of the WNBD
// parameters, which can be used to determine the application managing
// a disk. We'll ignore other disks.
#define RBD_WNBD_OWNER_NAME "ceph-rbd-wnbd"

class WnbdHandler;

class WnbdAdminHook : public AdminSocketHook {
  WnbdHandler *m_handler;

public:
  explicit WnbdAdminHook(WnbdHandler *handler) :
        m_handler(handler) {
    g_ceph_context->get_admin_socket()->register_command(
      "wnbd stats", this, "get WNBD stats");
  }
  ~WnbdAdminHook() override {
    g_ceph_context->get_admin_socket()->unregister_commands(this);
  }

  int call(std::string_view command, const cmdmap_t& cmdmap,
     Formatter *f, std::ostream& errss, bufferlist& out) override;
};


class WnbdHandler
{
private:
  librbd::Image &image;
  std::string instance_name;
  uint32_t block_count;
  uint32_t block_size;
  bool readonly;
  uint32_t thread_count;
  bool started;

  WnbdAdminHook* admin_hook;
  WnbdLogLevel wnbd_log_level;

public:
  WnbdHandler(librbd::Image& _image, std::string _instance_name,
              uint32_t _block_count, uint32_t _block_size,
              bool _readonly,
              uint32_t _thread_count,
              WnbdLogLevel _wnbd_log_level)
    : image(_image)
    , instance_name(_instance_name)
    , block_count(_block_count)
    , block_size(_block_size)
    , readonly(_readonly)
    , thread_count(_thread_count)
    , started(false)
    , wnbd_log_level(_wnbd_log_level)
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
    admin_hook = new WnbdAdminHook(this);
  }

  int start();
  // Wait for the handler to stop, which normally happens when the driver
  // passes the "Disconnect" request.
  int wait();
  void shutdown();

  int dump_stats(Formatter *f);

  ~WnbdHandler();

private:
  ceph::mutex shutdown_lock = ceph::make_mutex("WnbdHandler::DisconnectLocker");
  bool terminated = false;
  std::atomic<bool> allow_internal_flush = { false };
  WNBD_DEVICE* wnbd_device = nullptr;

  struct IOContext
  {
    xlist<IOContext*>::item item;
    WnbdHandler *handler = nullptr;
    WNBD_STATUS wnbd_status = {0};
    WnbdRequestType req_type = WnbdReqTypeUnknown;
    uint64_t req_handle = 0;
    uint32_t err_code = 0;
    uint32_t req_size;
    uint32_t req_from;
    bufferlist data;

    IOContext()
      : item(this)
    {}

    void set_sense(uint8_t sense_key, uint8_t asc, uint64_t info);
    void set_sense(uint8_t sense_key, uint8_t asc);
  };

  friend std::ostream &operator<<(std::ostream &os, const IOContext &ctx);

  ceph::mutex lock = ceph::make_mutex("WnbdHandler::Locker");
  ceph::condition_variable cond;

  void send_io_response(IOContext *ctx);

  static void aio_callback(librbd::completion_t cb, void *arg);

  // WNBD IO entry points
  static void Read(
    PWNBD_DEVICE Device,
    UINT64 RequestHandle,
    PVOID Buffer,
    UINT64 BlockAddress,
    UINT32 BlockCount,
    BOOLEAN ForceUnitAccess);
  static void Write(
    PWNBD_DEVICE Device,
    UINT64 RequestHandle,
    PVOID Buffer,
    UINT64 BlockAddress,
    UINT32 BlockCount,
    BOOLEAN ForceUnitAccess);
  static VOID LogMessage(
    PWNBD_DEVICE Device,
    WnbdLogLevel LogLevel,
    const char* Message,
    const char* FileName,
    UINT32 Line,
    const char* FunctionName);

  static constexpr WNBD_INTERFACE RbdWnbdInterface =
  {
    Read,
    Write,
    nullptr,
    nullptr,
    LogMessage
  };
};

std::ostream &operator<<(std::ostream &os, const WnbdHandler::IOContext &ctx);

#endif // WNBD_HANDLER_H
