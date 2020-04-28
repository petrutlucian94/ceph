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

#include "include/int_types.h"

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <process.h>

#include <sys/socket.h>

#include <boost/filesystem.hpp>
#include <boost/locale/encoding_utf.hpp>
#include "wnbd_wmi.h"
#include "wnbd_ioctl.h"
#include "userspace_shared.h"
#include "nbd-win32.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <regex>
#include <boost/algorithm/string/predicate.hpp>

#include "common/Formatter.h"
#include "common/TextTable.h"
#include "common/ceph_argparse.h"
#include "common/config.h"
#include "common/dout.h"
#include "common/errno.h"
#include "common/module.h"
#include "common/safe_io.h"
#include "common/version.h"
#include "common/win32_registry.h"
#include "common/win32_service.h"

#include "global/global_init.h"

#include "include/compat.h"
#include "include/rados/librados.hpp"
#include "include/rbd/librbd.hpp"
#include "include/stringify.h"
#include "include/xlist.h"

#include "mon/MonClient.h"

#include <shellapi.h>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "rbd-nbd: "

#define SERVICE_REG_KEY "SYSTEM\\CurrentControlSet\\Services\\rbd-nbd"

#define WNBD_STATUS_CONNECTED "connected"
#define WNBD_STATUS_DISCONNECTED "disconnected"

static BOOL WINAPI ConsoleHandlerRoutine(DWORD dwCtrlType);
using boost::locale::conv::utf_to_utf;

struct Config {
  int nbds_max = 0;
  int max_part = 255;
  int timeout = -1;

  bool exclusive = false;
  bool readonly = false;
  bool set_max_part = false;

  intptr_t parent_pipe = 0;
  int service = 0;

  std::string poolname;
  std::string nsname;
  std::string imgname;
  std::string snapname;
  std::string devpath;

  std::string format;
  bool pretty_format = false;

  // TODO: consider adding a "ConnectionInfo" structure.
  // The disk number is provided by Windows.
  int disk_number = -1;
  int pid = 0;
  std::string serial_number;
  bool connected = false;
  bool wnbd_mapped = false;
  std::string command_line;
};

std::string get_device_name_per_pid(int pid);
static bool map_device_using_suprocess(std::string command_line);
static int do_unmap(Config *cfg);
int load_mapping_config_from_registry(char* devpath, Config* cfg);


std::wstring to_wstring(const std::string& str)
{
    return utf_to_utf<wchar_t>(str.c_str(), str.c_str() + str.size());
}

std::string to_string(const std::wstring& str)
{
    return utf_to_utf<char>(str.c_str(), str.c_str() + str.size());
}

bool is_process_running(DWORD pid)
{
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    DWORD ret = WaitForSingleObject(process, 0);
    CloseHandle(process);
    return ret == WAIT_TIMEOUT;
}

// Iterate over mapped devices, retrieving info from the WNBD driver.
class WNBDActiveDiskIterator {
public:
  WNBDActiveDiskIterator() {
    DWORD status = WnbdList(&disk_list);
    if (!status || !disk_list) {
      derr << "Could not get WNBD devices. Return code: " << status << dendl;
    }
  }

  ~WNBDActiveDiskIterator() {
    if(disk_list) {
      free(disk_list);
      disk_list = NULL;
    }
  }

  bool get(Config *cfg) {
    index += 1;

    if(!disk_list || index >= disk_list->ActiveListCount) {
      return false;
    }

    USER_IN conn_info = disk_list->ActiveEntry[index].ConnectionInformation;
    load_mapping_config_from_registry(conn_info.InstanceName, cfg);

    int disk_number = GetDiskNumberBySerialNumber(
      to_wstring(conn_info.SerialNumber));

    if (disk_number < 0) {
      derr << "could not get disk number for current device: "
           << conn_info.InstanceName << dendl;
      cfg->disk_number = -1;
    }
    else {
      cfg->disk_number = disk_number;
    }

    cfg->serial_number = std::string(conn_info.SerialNumber);
    cfg->pid = conn_info.Pid;
    cfg->connected = cfg->disk_number && is_process_running(conn_info.Pid);
    cfg->wnbd_mapped = true;

    return true;
  }

private:
  PGET_LIST_OUT disk_list = NULL;
  int index = -1;
};

// Iterate over the Windows registry key, retrieving registered mappings.
class RegistryDiskIterator {
public:
  RegistryDiskIterator() {
    init();
  }

  int init() {
    reg_key = RegistryKey::open(g_ceph_context, HKEY_LOCAL_MACHINE,
                                SERVICE_REG_KEY, false);
    if(!reg_key) {
      return -EINVAL;
    }

    if(RegQueryInfoKey(
        reg_key->hKey, NULL, NULL, NULL,
        &subkey_count,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL))
      return -EINVAL;

    return 0;
  }

  bool get(Config *cfg) {
    index += 1;

    if (!reg_key || !subkey_count || index >= subkey_count)
      return false;

    DWORD subkey_name_sz = MAX_PATH;
    if(RegEnumKeyEx(reg_key->hKey, index, subkey_name, &subkey_name_sz,
                    NULL, NULL, NULL, NULL))
      return false;

    return load_mapping_config_from_registry(subkey_name, cfg) == 0;
  }

private:
  int index = -1;
  DWORD subkey_count = 0;
  char subkey_name[MAX_PATH];
  std::optional<RegistryKey> reg_key;
};

// Iterate over all RBD mappings, getting info from the registry and WNBD.
class WNBDDiskIterator {
public:
  bool get(Config *cfg) {
    bool found_active = active_iterator.get(cfg);
    if (found_active) {
      active_devices.insert(cfg->devpath);
      return true;
    }

    while(registry_iterator.get(cfg)) {
      if (active_devices.find(cfg->devpath) != active_devices.end()) {
        // Skip active devices that were already yielded.
        continue;
      }
      return true;
    }

    return false;
  }

private:
  // We'll keep track of the active devices.
  std::set<std::string> active_devices;

  WNBDActiveDiskIterator active_iterator;
  RegistryDiskIterator registry_iterator;
};

void
daemonize_complete(HANDLE parent_pipe)
{
    // If running as a child because '--detach' option was specified,
    // communicate with the parent to inform that the child is ready.
    // TODO: consider exiting in this case. The parent didn't wait for us,
    // maybe it was killed after a timeout.
    if (!WriteFile(parent_pipe, "a", 1, NULL, NULL)) {
        derr << "Failed to communicate with the parent: "
             << win32_lasterror_str() << dendl;
    }

    global_init_postfork_finish(g_ceph_context);
}

/* Spawn a subprocess using the specified command line, which is expected
   to be a "rbd-nbd map" command. A pipe is passed to the child process,
   which will allow it to communicate the mapping status */
static bool map_device_using_suprocess(std::string command_line)
{
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE read_pipe = NULL, write_pipe = NULL;
    char buffer[4096];
    char ch;
    DWORD exit_code = 0;

    dout(5) << __func__ << ": command_line: " << command_line << dendl;

    // We may get a command line containign an old pipe handle when
    // recreating mappings, so we'll have to remove it.
    std::regex pattern("(--pipe-handle [\'\"]?\\d+[\'\"]?)");
    command_line = std::regex_replace(command_line, pattern, "");

    /* Set the security attribute such that a process created will
     * inherit the pipe handles. */
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    /* Create an anonymous pipe to communicate with the child. */
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
        derr << "CreatePipe failed: " << win32_lasterror_str() << dendl;
    }

    GetStartupInfo(&si);

    /* Pass an extra argument '--pipe-handle <write_pipe>' */
    sprintf(buffer, "%s %s %lld", command_line.c_str(), "--pipe-handle",
        (intptr_t)write_pipe);

    /* Create a detached child */
    if (!CreateProcess(NULL, buffer, NULL, NULL, TRUE, DETACHED_PROCESS,
                      NULL, NULL, &si, &pi)) {
        derr << "CreateProcess failed: " << win32_lasterror_str() << dendl;
        exit_code = -1;
        goto finally;
    }

    /* Close one end of the pipe in the parent. */
    CloseHandle(write_pipe);
    write_pipe = NULL;

    /* Block and wait for child to say it is ready. */
    if (!ReadFile(read_pipe, &ch, 1, NULL, NULL)) {
        // TODO: this is quite unlikely, but we should kill the subprocess and
        // return an error.
        derr << "Failed to read from child: " << win32_lasterror_str() << dendl;
        if (!is_process_running(pi.dwProcessId)) {
            GetExitCodeProcess(pi.hProcess, &exit_code);
            derr << "Child failed with exit code: " << exit_code << dendl;
        }
    }

    finally:
      if(write_pipe)
        CloseHandle(write_pipe);
      if(read_pipe)
        CloseHandle(read_pipe);
    return exit_code;
}

void UnmapAtExit(void)
{
  std::string devpath = get_device_name_per_pid(getpid());
  if (devpath.empty()) {
      return;
  }
  WnbdUnmap((char *)devpath.c_str());
}

BOOL WINAPI ConsoleHandlerRoutine(DWORD dwCtrlType)
{
    exit(1);
    return true;
}

std::string get_device_name_per_pid(int pid)
{
    Config cfg;
    WNBDActiveDiskIterator wnbd_disk_iterator;

    while(wnbd_disk_iterator.get(&cfg)) {
      if (pid == cfg.pid) {
        return cfg.devpath;
      }
    }
    return std::string("");
}

int map_registry_config(Config* cfg)
{
    std::string strKey{ SERVICE_REG_KEY };
    strKey.append("\\");
    strKey.append(cfg->devpath);
    auto reg_key = RegistryKey::open(
      g_ceph_context, HKEY_LOCAL_MACHINE, strKey.c_str(), true);
    if (!reg_key) {
        return -EINVAL;
    }

    int ret_val = 0;
    if (reg_key->set("pid", getpid()) ||
        reg_key->set("devpath", cfg->devpath) ||
        reg_key->set("poolname", cfg->poolname) ||
        reg_key->set("nsname", cfg->nsname) ||
        reg_key->set("imgname", cfg->imgname) ||
        reg_key->set("snapname", cfg->snapname) ||
        reg_key->set("command_line", GetCommandLine())) {
        ret_val = -EINVAL;
    }

    // Registry writes are immediately available to other processes.
    // Still, we'll do a flush to ensure that the mapping can be
    // recreated after a system crash.
    reg_key->flush();
    return ret_val;
}

int unmap_registry_config(Config* cfg)
{
    std::string strKey{ SERVICE_REG_KEY };
    strKey.append("\\");
    strKey.append(cfg->devpath);
    return RegistryKey::remove(g_ceph_context, HKEY_LOCAL_MACHINE, strKey.c_str());
}

int load_mapping_config_from_registry(char* devpath, Config* cfg)
{
    std::string strKey{ SERVICE_REG_KEY };
    strKey.append("\\");
    strKey.append(devpath);
    auto reg_key = RegistryKey::open(
      g_ceph_context, HKEY_LOCAL_MACHINE, strKey.c_str(), false);
    if (!reg_key) {
        return -EINVAL;
    }
    std::string reg_value;

    if (!reg_key->get("devpath", reg_value)) {
        cfg->devpath = reg_value;
    }
    if (!reg_key->get("poolname", reg_value)) {
        cfg->poolname = reg_value;
    }
    if (!reg_key->get("nsname", reg_value)) {
        cfg->nsname = reg_value;
    }
    if (!reg_key->get("imgname", reg_value)) {
        cfg->imgname = reg_value;
    }
    if (!reg_key->get("snapname", reg_value)) {
        cfg->snapname = reg_value;
    }
    if (!reg_key->get("command_line", reg_value)) {
        cfg->command_line = reg_value;
    }

    return 0;
}

int restart_registered_mappings()
{
    Config cfg;
    WNBDDiskIterator iterator;
    int last_err = 0;

    while(iterator.get(&cfg)) {
      if(cfg.command_line.empty()) {
        derr << "Could not recreate mapping, missing command line: "
             << cfg.devpath << dendl;
        last_err = -EINVAL;
        continue;
      }
      if(cfg.wnbd_mapped) {
        dout(5) << __func__ << ": device already mapped: "
                << cfg.devpath << dendl;
        continue;
      }

      last_err = map_device_using_suprocess(cfg.command_line) || last_err;
    }

    return last_err;
}

int disconnect_all_mappings()
{
    Config cfg;
    WNBDActiveDiskIterator iterator;
    int last_err = 0;

    while(iterator.get(&cfg)) {
      last_err = do_unmap(&cfg) || last_err;
    }

    return last_err;
}

class RBDService : public Win32Service {
    // TODO: ensure that the ceph context is available when running the
    // service.
  public:
    RBDService(): Win32Service(g_ceph_context) {}

    int run_hook() override {
        return restart_registered_mappings();
    }
    /* Invoked when the service is requested to stop. */
    int stop_hook() override {
        return disconnect_all_mappings();
    }
    /* Invoked when the system is shutting down. */
    int shutdown_hook() override {
        return stop_hook();
    }
};

static void usage()
{
  std::cout << "Usage: rbd-nbd [options] map <image-or-snap-spec>                   Map an image to nbd device\n"
            << "               unmap <device|image-or-snap-spec>                    Unmap nbd device\n"
            << "               [options] <list|list-mapped>                         List mapped nbd devices\n"
            << "               [options] <show|show-mapped> <image-or-snap-spec>    Show mapped nbd device\n"
            << "Map options:\n"
            << "  --device <device path>  Specify nbd device path (/dev/nbd{num})\n"
            << "\n"
            << "Show|List options:\n"
            << "  --format plain|json|xml Output format (default: plain)\n"
            << "  --pretty-format         Pretty formatting (json and xml)\n"
            << std::endl;
  generic_server_usage();
}


typedef HANDLE NBD_FD_TYPE;

static NBD_FD_TYPE nbd = INVALID_HANDLE_VALUE;
static int nbd_index = -1;

enum Command {
  None,
  Connect,
  Disconnect,
  List,
  Show,
  Service
};

static Command cmd = None;

#define RBD_NBD_BLKSIZE 512UL

#define HELP_INFO 1
#define VERSION_INFO 2

#ifdef CEPH_BIG_ENDIAN
#define ntohll(a) (a)
#elif defined(CEPH_LITTLE_ENDIAN)
#define ntohll(a) swab(a)
#else
#error "Could not determine endianess"
#endif
#define htonll(a) ntohll(a)

static int parse_args(vector<const char*>& args, std::ostream *err_msg,
                      Command *command, Config *cfg);

class NBDServer
{
private:
  int fd;
  librbd::Image &image;

public:
  NBDServer(int _fd, librbd::Image& _image)
    : fd(_fd)
    , image(_image)
    , reader_thread(*this, &NBDServer::reader_entry)
    , writer_thread(*this, &NBDServer::writer_entry)
    , started(false)
  {}

private:
  ceph::mutex disconnect_lock =
    ceph::make_mutex("NBDServer::DisconnectLocker");
  ceph::condition_variable disconnect_cond;
  std::atomic<bool> terminated = { false };

  void shutdown()
  {
    bool expected = false;
    if (terminated.compare_exchange_strong(expected, true)) {
      ::shutdown(fd, SHUT_RDWR);

      std::lock_guard l{lock};
      cond.notify_all();
    }
  }

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

  void io_start(IOContext *ctx)
  {
    std::lock_guard l{lock};
    io_pending.push_back(&ctx->item);
  }

  void io_finish(IOContext *ctx)
  {
    std::lock_guard l{lock};
    ceph_assert(ctx->item.is_on_list());
    ctx->item.remove_myself();
    io_finished.push_back(&ctx->item);
    cond.notify_all();
  }

  IOContext *wait_io_finish()
  {
    std::unique_lock l{lock};
    cond.wait(l, [this] { return !io_finished.empty() || terminated; });

    if (io_finished.empty())
      return NULL;

    IOContext *ret = io_finished.front();
    io_finished.pop_front();

    return ret;
  }

  void wait_clean()
  {
    ceph_assert(!reader_thread.is_started());
    std::unique_lock l{lock};
    cond.wait(l, [this] { return io_pending.empty(); });

    while(!io_finished.empty()) {
      std::unique_ptr<IOContext> free_ctx(io_finished.front());
      io_finished.pop_front();
    }
  }

  static void aio_callback(librbd::completion_t cb, void *arg)
  {
    librbd::RBD::AioCompletion *aio_completion =
    reinterpret_cast<librbd::RBD::AioCompletion*>(cb);

    IOContext *ctx = reinterpret_cast<IOContext *>(arg);
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

  void reader_entry()
  {
    while (!terminated) {
      std::unique_ptr<IOContext> ctx(new IOContext());
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

      IOContext *pctx = ctx.release();
      io_start(pctx);
      librbd::RBD::AioCompletion *c = new librbd::RBD::AioCompletion(pctx, aio_callback);
      switch (pctx->command)
      {
        case NBD_CMD_WRITE:
          image.aio_write(pctx->request.from, pctx->request.len, pctx->data, c);
          break;
        case NBD_CMD_READ:
          image.aio_read(pctx->request.from, pctx->request.len, pctx->data, c);
          break;
        case NBD_CMD_FLUSH:
          image.aio_flush(c);
          break;
        case NBD_CMD_TRIM:
          image.aio_discard(pctx->request.from, pctx->request.len, c);
          break;
        default:
          derr << *pctx << ": invalid request command" << dendl;
          c->release();
          goto signal;
      }
    }
    dout(20) << __func__ << ": terminated" << dendl;

signal:
    std::lock_guard l{disconnect_lock};
    disconnect_cond.notify_all();
  }

  void writer_entry()
  {
    while (!terminated) {
      dout(20) << __func__ << ": waiting for io request" << dendl;
      std::unique_ptr<IOContext> ctx(wait_io_finish());
      if (!ctx) {
        dout(20) << __func__ << ": no io requests, terminating" << dendl;
        return;
      }

      dout(20) << __func__ << ": got: " << *ctx << dendl;

      int r = safe_send(fd, &ctx->reply, sizeof(struct nbd_reply));
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
  } reader_thread, writer_thread;

  bool started;
public:
  void start()
  {
    if (!started) {
      dout(10) << __func__ << ": starting" << dendl;

      started = true;

      reader_thread.create("rbd_reader");
      writer_thread.create("rbd_writer");
    }
  }

  void wait_for_disconnect()
  {
    if (!started)
      return;

    std::unique_lock l{disconnect_lock};
    disconnect_cond.wait(l);
  }

  ~NBDServer()
  {
    if (started) {
      dout(10) << __func__ << ": terminating" << dendl;

      shutdown();

      reader_thread.join();
      writer_thread.join();

      wait_clean();

      started = false;
    }
  }
};

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

class NBDWatchCtx : public librbd::UpdateWatchCtx
{
private:
  NBD_FD_TYPE fd;
  int nbd_index;
  librados::IoCtx &io_ctx;
  librbd::Image &image;
  uint64_t size;
public:
  NBDWatchCtx(NBD_FD_TYPE _fd,
              int _nbd_index,
              librados::IoCtx &_io_ctx,
              librbd::Image &_image,
              uint64_t _size)
    : fd(_fd)
    , nbd_index(_nbd_index)
    , io_ctx(_io_ctx)
    , image(_image)
    , size(_size)
  { }

  ~NBDWatchCtx() override {}

  void handle_notify() override
  {
    librbd::image_info_t info;
    if (image.stat(info, sizeof(info)) == 0) {
      uint64_t new_size = info.size;
      int ret = 0;

      if (new_size != size) {
        dout(5) << "resize detected" << dendl;

        if (!ret)
          size = new_size;

        if (image.invalidate_cache() < 0)
          derr << "invalidate rbd cache failed" << dendl;
      }
    }
  }
};

static NBDServer *start_server(int fd, librbd::Image& image)
{
  NBDServer *server;

  server = new NBDServer(fd, image);
  server->start();

  return server;
}

static void construct_devpath_if_missing(Config* cfg) {
  // Windows doesn't allow us to request specific disk paths when mapping an
  // image. This will just be used by rbd-nbd and wnbd as an identifier.
  if (cfg->devpath.empty()) {
    if (!cfg->poolname.empty()) {
      cfg->devpath += cfg->poolname;
      cfg->devpath += '/';
    }
    if (!cfg->nsname.empty()) {
      cfg->devpath += cfg->nsname;
      cfg->devpath += '/';
    }
    // TODO: ensure that either the device path or the image name are set.
    if (!cfg->imgname.empty()) {
      cfg->devpath += cfg->imgname;
    } else if (!cfg->snapname.empty()) {
      cfg->devpath += cfg->snapname;
    }
  }
}

static int initialize_wnbd_connection(Config* cfg, unsigned long long size)
{
  // On Windows, we can't pass socket descriptors to our driver. Instead,
  // we're going to open a tcp server and request the driver to connect to it.
  union {
       struct sockaddr_in inaddr;
       struct sockaddr addr;
    } a;
  socklen_t addrlen = sizeof(a.inaddr);
  unsigned int conn = 0;
  unsigned int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listener == INVALID_SOCKET)
      return SOCKET_ERROR;

  memset(&a, 0, sizeof(a));
  a.inaddr.sin_family = AF_INET;
  a.inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.inaddr.sin_port = 0;

  if(bind(listener, &a.addr, addrlen) == SOCKET_ERROR)
    goto error;
  if(getsockname(listener, &a.addr, &addrlen) == SOCKET_ERROR)
    goto error;
  if(listen(listener, 1) == SOCKET_ERROR)
    goto error;

  char port[100];
  snprintf(port, 100, "%d", ntohs(a.inaddr.sin_port));
  char* hostname;
  hostname = inet_ntoa(a.inaddr.sin_addr);
  construct_devpath_if_missing(cfg);

  if (WnbdMap((char *)cfg->devpath.c_str(), hostname, port, (char *)"", size, FALSE)) {
      derr << "Failed to initialize NBD connection: "
           << win32_lasterror_str() << dendl;
      goto error;
  }

  conn = accept(listener, NULL, NULL);
  if (conn == INVALID_SOCKET)
      goto error;

  closesocket(listener);

  return conn;

  error:
    closesocket(listener);
    return -1;
}

static void run_server(NBDServer *server, HANDLE parent_pipe)
{
  if (g_conf()->daemonize) {
    daemonize_complete(parent_pipe);
  }
  server->wait_for_disconnect();
}

static int do_map(int argc, const char *argv[], Config *cfg)
{
  int r;

  librados::Rados rados;
  librbd::RBD rbd;
  librados::IoCtx io_ctx;
  librbd::Image image;

  uint64_t flags;
  uint64_t size;

  int fd = -1;

  librbd::image_info_t info;

  NBDServer *server;

  vector<const char*> args;
  argv_to_vec(argc, argv, args);
  if (args.empty()) {
    cerr << argv[0] << ": -h or --help for usage" << std::endl;
    exit(1);
  }
  if (ceph_argparse_need_usage(args)) {
    usage();
    exit(0);
  }

  auto cct = global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT,
                         CODE_ENVIRONMENT_DAEMON,
                         CINIT_FLAG_UNPRIVILEGED_DAEMON_DEFAULTS);
  g_ceph_context->_conf.set_val_or_die("pid_file", "");

  if (global_init_prefork(g_ceph_context) >= 0) {
    global_init_postfork_start(g_ceph_context);
  }

  common_init_finish(g_ceph_context);
  global_init_chdir(g_ceph_context);

  if (g_conf()->daemonize && !cfg->parent_pipe) {
    return map_device_using_suprocess(GetCommandLine());
  }

  r = rados.init_with_context(g_ceph_context);
  if (r < 0)
    goto close_fd;

  r = rados.connect();
  if (r < 0)
    goto close_fd;

  r = rados.ioctx_create(cfg->poolname.c_str(), io_ctx);
  if (r < 0)
    goto close_fd;

  io_ctx.set_namespace(cfg->nsname);

  r = rbd.open(io_ctx, image, cfg->imgname.c_str());
  if (r < 0)
    goto close_fd;

  if (cfg->exclusive) {
    r = image.lock_acquire(RBD_LOCK_MODE_EXCLUSIVE);
    if (r < 0) {
      cerr << "rbd-nbd: failed to acquire exclusive lock: " << cpp_strerror(r)
           << std::endl;
      goto close_fd;
    }
  }

  if (!cfg->snapname.empty()) {
    r = image.snap_set(cfg->snapname.c_str());
    if (r < 0)
      goto close_fd;
  }

  r = image.stat(info, sizeof(info));
  if (r < 0)
    goto close_fd;

  flags = NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_TRIM | NBD_FLAG_HAS_FLAGS;
  if (!cfg->snapname.empty() || cfg->readonly) {
    flags |= NBD_FLAG_READ_ONLY;
  }

  if (info.size > _UI64_MAX) {
    r = -EFBIG;
    cerr << "rbd-nbd: image is too large (" << byte_u_t(info.size)
         << ", max is " << byte_u_t(_UI64_MAX) << ")" << std::endl;
    goto close_fd;
  }

  size = info.size;

  fd = initialize_wnbd_connection(cfg, size);
  if (fd < 0) {
      r = -1;
      goto close_ret;
  }
  atexit(UnmapAtExit);
  r = map_registry_config(cfg);
  if (r < 0)
      goto close_nbd;

  server = start_server(fd, image);

  {
    uint64_t handle;

    NBDWatchCtx watch_ctx(nbd, nbd_index, io_ctx, image, info.size);
    r = image.update_watch(&watch_ctx, &handle);
    if (r < 0)
      goto close_nbd;

    cout << cfg->devpath << std::endl;

    run_server(server, (HANDLE)cfg->parent_pipe);

    r = image.update_unwatch(handle);
    ceph_assert(r == 0);
  }

close_nbd:
  if (r < 0) {
    WnbdUnmap((char *)cfg->devpath.c_str());
  }

  delete server;
close_fd:
  compat_closesocket(fd);
close_ret:
  image.close();
  io_ctx.close();
  rados.shutdown();

  return r;
}

static int do_unmap(Config *cfg)
{
  DWORD r;
  construct_devpath_if_missing(cfg);
  r = WnbdUnmap((char *)cfg->devpath.c_str());
  if (r != 0) {
      cerr << "rbd-nbd: failed to unmap device: " << cfg->devpath << " with last error: " << r << std::endl;
      if (r == ERROR_FILE_NOT_FOUND)
        return -ENODEV;
      else
        return -EINVAL;
  }
  unmap_registry_config(cfg);
  return 0;
}

static int parse_imgpath(const std::string &imgpath, Config *cfg,
                         std::ostream *err_msg) {
  std::regex pattern("^(?:([^/]+)/(?:([^/@]+)/)?)?([^@]+)(?:@([^/@]+))?$");
  std::smatch match;
  if (!std::regex_match(imgpath, match, pattern)) {
    std::cerr << "rbd-nbd: invalid spec '" << imgpath << "'" << std::endl;
    return -EINVAL;
  }

  if (match[1].matched) {
    cfg->poolname = match[1];
  }

  if (match[2].matched) {
    cfg->nsname = match[2];
  }

  cfg->imgname = match[3];

  if (match[4].matched)
    cfg->snapname = match[4];

  return 0;
}

/* List mapped devices. If "search_devpath" is set, only this specific device
   will be printed. */
static int do_list_mapped_devices(const std::string &format, bool pretty_format,
                                  std::string search_devpath)
{
  bool should_print = false;
  std::unique_ptr<ceph::Formatter> f;
  TextTable tbl;

  if (format == "json") {
    f.reset(new JSONFormatter(pretty_format));
  } else if (format == "xml") {
    f.reset(new XMLFormatter(pretty_format));
  } else if (!format.empty() && format != "plain") {
    std::cerr << "rbd-nbd: invalid output format: " << format << std::endl;
    return -EINVAL;
  }

  if (f) {
    f->open_array_section("devices");
  } else {
    tbl.define_column("id", TextTable::LEFT, TextTable::LEFT);
    tbl.define_column("pool", TextTable::LEFT, TextTable::LEFT);
    tbl.define_column("namespace", TextTable::LEFT, TextTable::LEFT);
    tbl.define_column("image", TextTable::LEFT, TextTable::LEFT);
    tbl.define_column("snap", TextTable::LEFT, TextTable::LEFT);
    tbl.define_column("device", TextTable::LEFT, TextTable::LEFT);
    tbl.define_column("disk_number", TextTable::LEFT, TextTable::LEFT);
    tbl.define_column("status", TextTable::LEFT, TextTable::LEFT);
  }

  Config cfg;
  WNBDDiskIterator wnbd_disk_iterator;
  bool found = false;

  while(wnbd_disk_iterator.get(&cfg)) {
    if(!search_devpath.empty()) {
      if(cfg.devpath != search_devpath)
        continue;
      found = true;
    }
    const char* status = cfg.connected ?
      WNBD_STATUS_CONNECTED : WNBD_STATUS_DISCONNECTED;

    if (f) {
      f->open_object_section("device");
      f->dump_int("id", cfg.pid);
      f->dump_string("device", cfg.devpath);
      f->dump_string("pool", cfg.poolname);
      f->dump_string("namespace", cfg.nsname);
      f->dump_string("image", cfg.imgname);
      f->dump_string("snap", cfg.snapname);
      f->dump_int("disk_number", cfg.disk_number);
      f->dump_string("status", status);
      f->close_section();
  } else {
      should_print = true;
      if (cfg.snapname.empty()) {
          cfg.snapname = "-";
      }
      tbl << cfg.pid << cfg.poolname << cfg.nsname
          << cfg.imgname << cfg.snapname << cfg.devpath
          << cfg.disk_number << status << TextTable::endrow;
    }
  }

  if (f) {
    f->close_section(); // devices
    f->flush(std::cout);
  }
  if (should_print) {
    std::cout << tbl;
  }
  if (!search_devpath.empty() && !found) {
      return -ENOENT;
  }

  return 0;
}

static int parse_args(vector<const char*>& args, std::ostream *err_msg,
                      Command *command, Config *cfg) {
  std::string conf_file_list;
  std::string cluster;
  CephInitParameters iparams = ceph_argparse_early_args(
          args, CEPH_ENTITY_TYPE_CLIENT, &cluster, &conf_file_list);

  ConfigProxy config{false};
  config->name = iparams.name;
  config->cluster = cluster;

  if (!conf_file_list.empty()) {
    config.parse_config_files(conf_file_list.c_str(), nullptr, 0);
  } else {
    config.parse_config_files(nullptr, nullptr, 0);
  }
  config.parse_env(CEPH_ENTITY_TYPE_CLIENT);
  config.parse_argv(args);
  cfg->poolname = config.get_val<std::string>("rbd_default_pool");

  std::vector<const char*>::iterator i;
  std::ostringstream err;

  for (i = args.begin(); i != args.end(); ) {
    if (ceph_argparse_flag(args, i, "-h", "--help", (char*)NULL)) {
      return HELP_INFO;
    } else if (ceph_argparse_flag(args, i, "-v", "--version", (char*)NULL)) {
      return VERSION_INFO;
    } else if (ceph_argparse_witharg(args, i, &cfg->devpath, "--device", (char *)NULL)) {
    } else if (ceph_argparse_witharg(args, i, &cfg->format, err, "--format",
                                     (char *)NULL)) {
    } else if (ceph_argparse_flag(args, i, "--pretty-format", (char *)NULL)) {
      cfg->pretty_format = true;
    } else if (ceph_argparse_witharg(args, i, &cfg->parent_pipe, err, "--pipe-handle", (char *)NULL)) {
      if (!err.str().empty()) {
        *err_msg << "rbd-nbd: " << err.str();
        return -EINVAL;
      }
      if (cfg->parent_pipe < 0) {
        *err_msg << "rbd-nbd: Invalid argument for pipe-handle!";
        return -EINVAL;
      }
    } else {
      ++i;
    }
  }

  Command cmd = None;
  if (args.begin() != args.end()) {
    if (strcmp(*args.begin(), "map") == 0) {
      cmd = Connect;
    } else if (strcmp(*args.begin(), "unmap") == 0) {
      cmd = Disconnect;
    } else if (strcmp(*args.begin(), "list-mapped") == 0) {
      cmd = List;
    } else if (strcmp(*args.begin(), "list") == 0) {
      cmd = List;
    } else if (strcmp(*args.begin(), "show-mapped") == 0) {
      cmd = Show;
    } else if (strcmp(*args.begin(), "show") == 0) {
      cmd = Show;
    } else if (strcmp(*args.begin(), "service") == 0) {
      cmd = Service;
    } else {
      *err_msg << "rbd-nbd: unknown command: " <<  *args.begin();
      return -EINVAL;
    }
    args.erase(args.begin());
  }

  if (cmd == None) {
    *err_msg << "rbd-nbd: must specify command";
    return -EINVAL;
  }

  switch (cmd) {
    case Connect:
      if (args.begin() == args.end()) {
        *err_msg << "rbd-nbd: must specify image-or-snap-spec";
        return -EINVAL;
      }
      if (parse_imgpath(*args.begin(), cfg, err_msg) < 0) {
        return -EINVAL;
      }
      args.erase(args.begin());
      break;
    case Disconnect:
      if (args.begin() == args.end()) {
        *err_msg << "rbd-nbd: must specify nbd device or image-or-snap-spec";
        return -EINVAL;
      }
      if (boost::starts_with(*args.begin(), "/dev/")) {
        cfg->devpath = *args.begin();
      } else {
        if (parse_imgpath(*args.begin(), cfg, err_msg) < 0) {
          return -EINVAL;
        }
      }
      args.erase(args.begin());
      break;
    case Show:
      if (args.begin() == args.end()) {
        *err_msg << "rbd-nbd: must specify nbd device or image-or-snap-spec";
        return -EINVAL;
      }
      if (boost::starts_with(*args.begin(), "/dev/")) {
        cfg->devpath = *args.begin();
      } else {
        if (parse_imgpath(*args.begin(), cfg, err_msg) < 0) {
          return -EINVAL;
        }
      }
      args.erase(args.begin());
      break;
    default:
      //shut up gcc;
      break;
  }

  if (args.begin() != args.end()) {
    *err_msg << "rbd-nbd: unknown args: " << *args.begin();
    return -EINVAL;
  }

  *command = cmd;
  return 0;
}

static int rbd_nbd(int argc, const char *argv[])
{
  int r;
  Config cfg;
  vector<const char*> args;
  argv_to_vec(argc, argv, args);

  std::ostringstream err_msg;
  r = parse_args(args, &err_msg, &cmd, &cfg);
  if (r == HELP_INFO) {
    usage();
    return 0;
  } else if (r == VERSION_INFO) {
    std::cout << pretty_version_to_str() << std::endl;
    return 0;
  } else if (r < 0) {
    cerr << err_msg.str() << std::endl;
    return r;
  }

  switch (cmd) {
    case Connect:
      if (cfg.imgname.empty()) {
        cerr << "rbd-nbd: image name was not specified" << std::endl;
        return -EINVAL;
      }

      r = do_map(argc, argv, &cfg);
      if (r < 0)
        return -EINVAL;
      break;
    case Disconnect:
      r = do_unmap(&cfg);
      if (r < 0)
        return r;
      break;
    case List:
      r = do_list_mapped_devices(cfg.format, cfg.pretty_format, "");
      if (r < 0)
        return -EINVAL;
      break;
    case Show:
      construct_devpath_if_missing(&cfg);
      r = do_list_mapped_devices(cfg.format, cfg.pretty_format, cfg.devpath);
      if (r < 0)
        return -EINVAL;
      break;
    case Service:
      RBDService service;
      // This call will block until the service stops.
      r = RBDService::initialize(&service);
      if (r < 0)
          return -EINVAL;
      break;
    default:
      usage();
      break;
  }

  return 0;
}

int main(int argc, const char *argv[])
{
  SetConsoleCtrlHandler(ConsoleHandlerRoutine, true);
  /* The system does not display the Windows Error Reporting dialog. */
  SetErrorMode(GetErrorMode() | SEM_NOGPFAULTERRORBOX);
  InitWMI();
  int r = rbd_nbd(argc, argv);
  if (r < 0) {
    return r;
  }
  return 0;
}
