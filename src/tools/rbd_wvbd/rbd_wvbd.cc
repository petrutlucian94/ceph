// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

/*
 * rbd-wvbd - RBD in userspace
 *
 * Copyright (C) 2015 - 2016 Kylin Corporation
 * Copyright (C) 2020 SUSE LINUX GmbH
 *
 * Author: Yunchuan Wen <yunchuan.wen@kylin-cloud.com>
 *         Li Wang <li.wang@kylin-cloud.com>
 *         Lucian Petrut <lpetrut@cloudbasesolutions.com>
 *         Alin Serdean <aserdean@cloudbasesolutions.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
*/

#include "include/int_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>

#include <boost/locale/encoding_utf.hpp>

#include "wvbd_handler.h"
#include "rbd_wvbd.h"

#include <fstream>
#include <memory>
#include <regex>

#include "common/Formatter.h"
#include "common/TextTable.h"
#include "common/ceph_argparse.h"
#include "common/config.h"
#include "common/dout.h"
#include "common/errno.h"
#include "common/module.h"
#include "common/version.h"
#include "common/win32/service.h"
#include "common/admin_socket_client.h"

#include "global/global_init.h"

#include "include/rados/librados.hpp"
#include "include/rbd/librbd.hpp"
#include "include/stringify.h"

#include "mon/MonClient.h"

#include <shellapi.h>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "rbd-wvbd: "

using boost::locale::conv::utf_to_utf;

std::wstring to_wstring(const std::string& str)
{
  return utf_to_utf<wchar_t>(str.c_str(), str.c_str() + str.size());
}


bool is_process_running(DWORD pid)
{
  HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
  DWORD ret = WaitForSingleObject(process, 0);
  CloseHandle(process);
  return ret == WAIT_TIMEOUT;
}

DWORD WVBDActiveDiskIterator::fetch_list(
  PWVBD_CONNECTION_LIST* conn_list)
{
  DWORD curr_buff_sz = 0;
  DWORD buff_sz = 0;
  DWORD err = ERROR_INSUFFICIENT_BUFFER;
  PWVBD_CONNECTION_LIST tmp_list = NULL;

  // We're using a loop because other connections may show up by the time
  // we retry.
  do {
    if (tmp_list)
      free(tmp_list);

    if (buff_sz) {
      tmp_list = (PWVBD_CONNECTION_LIST) calloc(1, buff_sz);
      if (!tmp_list) {
        derr << "Could not allocate " << buff_sz << " bytes." << dendl;
        err = ERROR_NOT_ENOUGH_MEMORY;
        break;
      }
    }

    curr_buff_sz = buff_sz;
    // If the buffer is too small, the return value is 0 and "BufferSize"
    // will contain the required size. This is counterintuitive, but
    // Windows drivers can't return a buffer as well as a non-zero status.
    err = WvbdList(tmp_list, &buff_sz);
    if (err)
      break;
  } while (curr_buff_sz < buff_sz);

  if (err) {
    if (err == ERROR_OPEN_FAILED) {
      derr << "Could not open WNBD device. Make sure that the driver "
           << "is installed." << dendl;
    }
    else {
      derr << "Could not get WNBD devices. Return code: " << err << dendl;
    }

    if (tmp_list)
      free(tmp_list);
  }
  else {
    *conn_list = tmp_list;
  }
  return err;
}

WVBDActiveDiskIterator::WVBDActiveDiskIterator()
{
  DWORD status = WVBDActiveDiskIterator::fetch_list(&conn_list);

  if (status) {
    error = EINVAL;
  }
}

WVBDActiveDiskIterator::~WVBDActiveDiskIterator()
{
  if (conn_list) {
    free(conn_list);
    conn_list = NULL;
  }
}

bool WVBDActiveDiskIterator::get(Config *cfg)
{
  index += 1;
  *cfg = Config();

  if (!conn_list || index >= (int)conn_list->Count) {
    return false;
  }

  WVBD_PROPERTIES conn_props = conn_list->Connections[index].Properties;

  if (strncmp(conn_props.Owner, RBD_WVBD_OWNER_NAME, WVBD_MAX_OWNER_LENGTH)) {
    dout(10) << "Ignoring disk: " << conn_props.InstanceName
             << ". Owner: " << conn_props.Owner << dendl;
    return this->get(cfg);
  }

  error = load_mapping_config_from_registry(conn_props.InstanceName, cfg);
  if (error) {
    derr << "Could not load registry disk info for: "
         << conn_props.InstanceName << ". Error: " << error << dendl;
    return false;
  }

  int disk_number = -1;
  HRESULT hres = WvbdGetDiskNumberBySerialNumber(
    to_wstring(conn_props.SerialNumber).c_str(), (PDWORD)&disk_number);

  if (disk_number < 0) {
    derr << "could not get disk number for mapped device: "
         << conn_props.InstanceName << ". Error: " << hres << dendl;
    cfg->disk_number = -1;
  }
  else {
    cfg->disk_number = disk_number;
  }

  cfg->serial_number = std::string(conn_props.SerialNumber);
  cfg->pid = conn_props.Pid;
  cfg->active = cfg->disk_number > 0 && is_process_running(conn_props.Pid);
  cfg->registered = true;

  return true;
}

RegistryDiskIterator::RegistryDiskIterator()
{
  reg_key = new RegistryKey(g_ceph_context, HKEY_LOCAL_MACHINE,
                            SERVICE_REG_KEY, false);
  if (!reg_key->hKey) {
    if (!reg_key->missingKey)
      error = EINVAL;
    return;
  }

  if (RegQueryInfoKey(reg_key->hKey, NULL, NULL, NULL, &subkey_count,
                     NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
    derr << "Could not query registry key: " << SERVICE_REG_KEY << dendl;
    error = EINVAL;
    return;
  }
}

bool RegistryDiskIterator::get(Config *cfg)
{
  index += 1;
  *cfg = Config();

  if (!reg_key->hKey || !subkey_count || index >= (int)subkey_count) {
    return false;
  }

  char subkey_name[MAX_PATH] = {0};
  DWORD subkey_name_sz = MAX_PATH;
  if (RegEnumKeyEx(reg_key->hKey, index, subkey_name, &subkey_name_sz,
                   NULL, NULL, NULL, NULL)) {
    derr << "Could not enumerate registry subkey: " << subkey_name << dendl;
    error = EINVAL;
    return false;
  }

  if (load_mapping_config_from_registry(subkey_name, cfg)) {
    error = EINVAL;
    return false;
  };

  return true;
}

// Iterate over all RBD mappings, getting info from the registry and the driver.
bool WVBDDiskIterator::get(Config *cfg)
{
  *cfg = Config();

  bool found_active = active_iterator.get(cfg);
  if (found_active) {
    active_devices.insert(cfg->devpath);
    return true;
  }

  error = active_iterator.get_error();
  if (error) {
    dout(5) << ": WNBD iterator error: " << error << dendl;
    return false;
  }

  while(registry_iterator.get(cfg)) {
    if (active_devices.find(cfg->devpath) != active_devices.end()) {
      // Skip active devices that were already yielded.
      continue;
    }
    return true;
  }

  error = registry_iterator.get_error();
  if (error) {
    dout(5) << ": Registry iterator error: " << error << dendl;
  }
  return false;
}

/* Spawn a subprocess using the specified command line, which is expected
   to be a "rbd-wvbd map" command. A pipe is passed to the child process,
   which will allow it to communicate the mapping status */
bool map_device_using_suprocess(std::string command_line)
{
  SECURITY_ATTRIBUTES sa;
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  HANDLE read_pipe = NULL, write_pipe = NULL;
  char buffer[4096];
  char ch;
  DWORD exit_code = 0, err = 0;

  dout(5) << __func__ << ": command_line: " << command_line << dendl;

  // We may get a command line containing an old pipe handle when
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
    err = GetLastError();
    derr << "CreatePipe failed: " << win32_strerror(err) << dendl;
    exit_code = -1;
    goto finally;
  }

  GetStartupInfo(&si);

  /* Pass an extra argument '--pipe-handle <write_pipe>' */
  sprintf(buffer, "%s %s %lld", command_line.c_str(), "--pipe-handle",
          (intptr_t)write_pipe);

  /* Create a detached child */
  if (!CreateProcess(NULL, buffer, NULL, NULL, TRUE, DETACHED_PROCESS,
                     NULL, NULL, &si, &pi)) {
    err = GetLastError();
    derr << "CreateProcess failed: " << win32_strerror(err) << dendl;
    exit_code = -1;
    goto finally;
  }

  /* Close one end of the pipe in the parent. */
  CloseHandle(write_pipe);
  write_pipe = NULL;

  /* Block and wait for child to say it is ready. */
  dout(5) << __func__ << ": waiting for child notification." << dendl;
  if (!ReadFile(read_pipe, &ch, 1, NULL, NULL)) {
    err = GetLastError();
    derr << "Failed to read from child: " << win32_strerror(err) << dendl;
    if (!is_process_running(pi.dwProcessId)) {
        GetExitCodeProcess(pi.hProcess, &exit_code);
        derr << "Child failed with exit code: " << exit_code << dendl;
    }
    // The process closed the pipe without notifying us or exiting.
    // This is quite unlikely, but we'll terminate the process.
    else {
      dout(5) << "Terminating unresponsive process." << dendl;
      TerminateProcess(pi.hProcess, 1);
    }
  }
  else {
    dout(5) << __func__ << ": received child notification." << dendl;
  }

  finally:
    if (write_pipe)
      CloseHandle(write_pipe);
    if (read_pipe)
      CloseHandle(read_pipe);
  return exit_code;
}

BOOL WINAPI console_handler_routine(DWORD dwCtrlType)
{
  dout(5) << "Received control signal: " << dwCtrlType
          << ". Exiting." << dendl;

  std::unique_lock l{shutdown_lock};
  if (handler)
    handler->shutdown();

  return true;
}

int save_config_to_registry(Config* cfg)
{
  std::string strKey{ SERVICE_REG_KEY };
  strKey.append("\\");
  strKey.append(cfg->devpath);
  auto reg_key = RegistryKey(
    g_ceph_context, HKEY_LOCAL_MACHINE, strKey.c_str(), true);
  if (!reg_key.hKey) {
      return -EINVAL;
  }

  int ret_val = 0;
  // Registry writes are immediately available to other processes.
  // Still, we'll do a flush to ensure that the mapping can be
  // recreated after a system crash.
  if (reg_key.set("pid", getpid()) ||
      reg_key.set("devpath", cfg->devpath) ||
      reg_key.set("poolname", cfg->poolname) ||
      reg_key.set("nsname", cfg->nsname) ||
      reg_key.set("imgname", cfg->imgname) ||
      reg_key.set("snapname", cfg->snapname) ||
      reg_key.set("command_line", GetCommandLine()) ||
      reg_key.set("admin_sock_path", g_conf()->admin_socket) ||
      reg_key.flush()) {
    ret_val = -EINVAL;
  }

  return ret_val;
}

int remove_config_from_registry(Config* cfg)
{
  std::string strKey{ SERVICE_REG_KEY };
  strKey.append("\\");
  strKey.append(cfg->devpath);
  return RegistryKey::remove(
    g_ceph_context, HKEY_LOCAL_MACHINE, strKey.c_str());
}

int load_mapping_config_from_registry(char* devpath, Config* cfg)
{
  std::string strKey{ SERVICE_REG_KEY };
  strKey.append("\\");
  strKey.append(devpath);
  auto reg_key = RegistryKey(
    g_ceph_context, HKEY_LOCAL_MACHINE, strKey.c_str(), false);
  if (!reg_key.hKey) {
    return -EINVAL;
  }

  reg_key.get("devpath", cfg->devpath);
  reg_key.get("poolname", cfg->poolname);
  reg_key.get("nsname", cfg->nsname);
  reg_key.get("imgname", cfg->imgname);
  reg_key.get("snapname", cfg->snapname);
  reg_key.get("command_line", cfg->command_line);
  reg_key.get("admin_sock_path", cfg->admin_sock_path);

  return 0;
}

int restart_registered_mappings()
{
  Config cfg;
  WVBDDiskIterator iterator;
  int err = 0, r;

  while (iterator.get(&cfg)) {
    if (cfg.command_line.empty()) {
      derr << "Could not recreate mapping, missing command line: "
           << cfg.devpath << dendl;
      err = -EINVAL;
      continue;
    }
    if (cfg.registered) {
      dout(5) << __func__ << ": device already mapped: "
              << cfg.devpath << dendl;
      continue;
    }

    // We'll try to map all devices and return a non-zero value
    // if any of them fails.
    r = map_device_using_suprocess(cfg.command_line);
    if (r)
      err = r;
  }

  r = iterator.get_error();
  if (r) {
    derr << "Could not fetch all mappings. Error: " << r << dendl;
    err = r;
  }

  return err;
}

int disconnect_all_mappings(bool unregister)
{
  Config cfg;
  WVBDActiveDiskIterator iterator;
  int err = 0, r;

  while (iterator.get(&cfg)) {
    r = do_unmap(&cfg, unregister);
    if (r)
      err = r;
  }

  r = iterator.get_error();
  if (r)
    err = r;

  return err;
}

class RBDService : public ServiceBase {
  public:
    RBDService(): ServiceBase(g_ceph_context) {}

    int run_hook() override {
      return restart_registered_mappings();
    }
    /* Invoked when the service is requested to stop. */
    int stop_hook() override {
      return disconnect_all_mappings(false);
    }
    /* Invoked when the system is shutting down. */
    int shutdown_hook() override {
      return stop_hook();
    }
};

static void usage()
{
  std::cout << "Usage: rbd-wvbd [options] map <image-or-snap-spec>                   Map an image to wvbd device\n"
            << "                unmap <device|image-or-snap-spec>                    Unmap wvbd device\n"
            << "                [options] <list|list-mapped>                         List mapped wvbd devices\n"
            << "                [options] <show|show-mapped> <image-or-snap-spec>    Show mapped wvbd device\n"
            << "                <stats> <image-or-snap-spec>                         Show IO counters\n"
            << "Map options:\n"
            << "  --device <device path>  Optional mapping unique identifier\n"
            << "  --exclusive             Forbid writes by other clients\n"
            << "  --read-only             Map read-only\n"
            << "\n"
            << "Show|List options:\n"
            << "  --format plain|json|xml Output format (default: plain)\n"
            << "  --pretty-format         Pretty formatting (json and xml)\n"
            << std::endl;
  generic_server_usage();
}


static Command cmd = None;

int construct_devpath_if_missing(Config* cfg)
{
  // Windows doesn't allow us to request specific disk paths when mapping an
  // image. This will just be used by rbd-wvbd and wvbd as an identifier.
  if (cfg->devpath.empty()) {
    if (cfg->imgname.empty()) {
      derr << "Missing image name." << dendl;
      return -EINVAL;
    }

    if (!cfg->poolname.empty()) {
      cfg->devpath += cfg->poolname;
      cfg->devpath += '/';
    }
    if (!cfg->nsname.empty()) {
      cfg->devpath += cfg->nsname;
      cfg->devpath += '/';
    }

    cfg->devpath += cfg->imgname;

    if (!cfg->snapname.empty()) {
      cfg->devpath += '@';
      cfg->devpath += cfg->snapname;
    }
  }

  return 0;
}

boost::intrusive_ptr<CephContext> do_global_init(
      int argc, const char *argv[], Config *cfg)
{
  std::vector<const char*> args;
  argv_to_vec(argc, argv, args);

  code_environment_t code_env;
  int flags;

  switch(cmd) {
    case Connect:
      code_env = CODE_ENVIRONMENT_DAEMON;
      flags = CINIT_FLAG_UNPRIVILEGED_DAEMON_DEFAULTS;
      break;
    case Service:
      code_env = CODE_ENVIRONMENT_DAEMON;
      flags = CINIT_FLAG_UNPRIVILEGED_DAEMON_DEFAULTS |
              CINIT_FLAG_NO_MON_CONFIG;
      break;
    default:
      code_env = CODE_ENVIRONMENT_UTILITY;
      flags = CINIT_FLAG_NO_MON_CONFIG;
      break;
  }

  auto cct = global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT,
                         code_env, flags);
  // TODO: check if we still need to override this.
  g_ceph_context->_conf.set_val_or_die("pid_file", "");

  // TODO: Those can probably be dropped.
  if (global_init_prefork(g_ceph_context) >= 0) {
    global_init_postfork_start(g_ceph_context);
  }

  // There's no fork on Windows, we should be safe calling this anytime.
  common_init_finish(g_ceph_context);
  global_init_chdir(g_ceph_context);

  return cct;
}

static int do_map(Config *cfg)
{
  int r;

  librados::Rados rados;
  librbd::RBD rbd;
  librados::IoCtx io_ctx;
  librbd::Image image;
  librbd::image_info_t info;

  if (g_conf()->daemonize && !cfg->parent_pipe) {
    return map_device_using_suprocess(GetCommandLine());
  }

  r = rados.init_with_context(g_ceph_context);
  if (r < 0)
    goto close_ret;

  r = rados.connect();
  if (r < 0)
    goto close_ret;

  r = rados.ioctx_create(cfg->poolname.c_str(), io_ctx);
  if (r < 0)
    goto close_ret;

  io_ctx.set_namespace(cfg->nsname);

  r = rbd.open(io_ctx, image, cfg->imgname.c_str());
  if (r < 0)
    goto close_ret;

  if (cfg->exclusive) {
    r = image.lock_acquire(RBD_LOCK_MODE_EXCLUSIVE);
    if (r < 0) {
      derr << "rbd-wvbd: failed to acquire exclusive lock: " << cpp_strerror(r)
           << dendl;
      goto close_ret;
    }
  }

  if (!cfg->snapname.empty()) {
    r = image.snap_set(cfg->snapname.c_str());
    if (r < 0)
      goto close_ret;
  }

  r = image.stat(info, sizeof(info));
  if (r < 0)
    goto close_ret;

  if (info.size > _UI64_MAX) {
    r = -EFBIG;
    derr << "rbd-wvbd: image is too large (" << byte_u_t(info.size)
         << ", max is " << byte_u_t(_UI64_MAX) << ")" << dendl;
    goto close_ret;
  }

  r = save_config_to_registry(cfg);
  if (r < 0)
    goto close_ret;

  handler = new WvbdHandler(image, cfg->devpath,
                            info.size / RBD_WVBD_BLKSIZE,
                            RBD_WVBD_BLKSIZE,
                            cfg->readonly,
                            cfg->wvbd_thread_count,
                            cfg->wvbd_log_level);

  cout << cfg->devpath << std::endl;

  // We're informing the parent processes that the initialization
  // was successful.
  if (cfg->parent_pipe) {
    if (!WriteFile((HANDLE)cfg->parent_pipe, "a", 1, NULL, NULL)) {
      // TODO: consider exiting in this case. The parent didn't wait for us,
      // maybe it was killed after a timeout.
      int err = GetLastError();
      derr << "Failed to communicate with the parent: "
           << win32_strerror(err) << dendl;
    }
    else {
      dout(5) << __func__ << ": submitted parent notification." << dendl;
    }

    global_init_postfork_finish(g_ceph_context);
  }

  handler->start();
  handler->wait();
  handler->shutdown();

close_ret:
  std::unique_lock l{shutdown_lock};

  image.close();
  io_ctx.close();
  rados.shutdown();
  if (handler) {
    delete handler;
    handler = nullptr;
  }

  return r;
}

static int do_unmap(Config *cfg, bool unregister)
{
  int err = WvbdRemoveEx(cfg->devpath.c_str());
  if (err && err != ERROR_FILE_NOT_FOUND) {
    derr << "rbd-wvbd: could not disconnect image '" << cfg->devpath
         << "'. Error: " << err << dendl;
    return -EINVAL;
  }

  if (unregister) {
    err = remove_config_from_registry(cfg);
    if (err) {
      derr << "rbd-nbd: failed to unregister device: "
           << cfg->devpath << ". Error: " << err << dendl;
      return -EINVAL;
    }
  }
  return 0;
}

static int parse_imgpath(const std::string &imgpath, Config *cfg,
                         std::ostream *err_msg)
{
  std::regex pattern("^(?:([^/]+)/(?:([^/@]+)/)?)?([^@]+)(?:@([^/@]+))?$");
  std::smatch match;
  if (!std::regex_match(imgpath, match, pattern)) {
    derr << "rbd-wvbd: invalid spec '" << imgpath << "'" << dendl;
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
    derr << "rbd-nbd: invalid output format: " << format << dendl;
    return -EINVAL;
  }

  if (f && search_devpath.empty()) {
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
  WVBDDiskIterator wvbd_disk_iterator;
  bool found = false;

  while(wvbd_disk_iterator.get(&cfg)) {
    if(!search_devpath.empty()) {
      if(cfg.devpath != search_devpath)
        continue;
      found = true;
    }
    const char* status = cfg.active ?
      WVBD_STATUS_ACTIVE : WVBD_STATUS_INACTIVE;

    if (f) {
      f->open_object_section("device");
      f->dump_int("id", cfg.pid ? cfg.pid : -1);
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
    tbl << (cfg.pid ? cfg.pid : -1) << cfg.poolname << cfg.nsname
        << cfg.imgname << cfg.snapname << cfg.devpath
        << cfg.disk_number << status << TextTable::endrow;
    }
  }
  int error = wvbd_disk_iterator.get_error();
  if(error) {
    derr << "Could not get disk list: " << error << dendl;
    return -error;
  }

  if (f) {
    if(search_devpath.empty()) {
      // When printing all devices instead of a single one, we'll have
      // to close the "devices" section.
      f->close_section();
    }
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

static int do_stats(std::string search_devpath)
{
  Config cfg;
  WVBDDiskIterator wvbd_disk_iterator;

  while (wvbd_disk_iterator.get(&cfg)) {
    if (cfg.devpath != search_devpath)
      continue;

    AdminSocketClient client = AdminSocketClient(cfg.admin_sock_path);
    std::string output;
    std::string result = client.do_request("{\"prefix\":\"wvbd stats\"}",
                                           &output);
    if (!result.empty()) {
      std::cerr << "Admin socket error: " << result << std::endl;
      return -EINVAL;
    }

    std::cout << output << std::endl;
    return 0;
  }
  int error = wvbd_disk_iterator.get_error();
  if (!error) {
    error = -ENOENT;
  }

  derr << "Could not get disk list: " << error << dendl;
  return -error;
}

static int parse_args(std::vector<const char*>& args,
                      std::ostream *err_msg,
                      Command *command, Config *cfg)
{
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
    } else if (ceph_argparse_flag(args, i, "--read-only", (char *)NULL)) {
      cfg->readonly = true;
    } else if (ceph_argparse_flag(args, i, "--exclusive", (char *)NULL)) {
      cfg->exclusive = true;
    } else if (ceph_argparse_flag(args, i, "--pretty-format", (char *)NULL)) {
      cfg->pretty_format = true;
    } else if (ceph_argparse_witharg(args, i, &cfg->parent_pipe, err, "--pipe-handle", (char *)NULL)) {
      if (!err.str().empty()) {
        *err_msg << "rbd-wvbd: " << err.str();
        return -EINVAL;
      }
      if (cfg->parent_pipe < 0) {
        *err_msg << "rbd-wvbd: Invalid argument for pipe-handle!";
        return -EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, (int*)&cfg->wvbd_log_level,
                                     err, "--wvbd_log_level", (char *)NULL)) {
      if (!err.str().empty()) {
        *err_msg << "rbd-nbd: " << err.str();
        return -EINVAL;
      }
      if (cfg->wvbd_log_level < 0) {
        *err_msg << "rbd-nbd: Invalid argument for wvbd_log_level";
        return -EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, (int*)&cfg->wvbd_thread_count,
                                     err, "--wvbd_thread_count", (char *)NULL)) {
      if (!err.str().empty()) {
        *err_msg << "rbd-nbd: " << err.str();
        return -EINVAL;
      }
      if (cfg->wvbd_thread_count < 0) {
        *err_msg << "rbd-nbd: Invalid argument for wvbd_thread_count";
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
    } else if (strcmp(*args.begin(), "stats") == 0) {
      cmd = Stats;
    } else {
      *err_msg << "rbd-wvbd: unknown command: " <<  *args.begin();
      return -EINVAL;
    }
    args.erase(args.begin());
  }

  if (cmd == None) {
    *err_msg << "rbd-wvbd: must specify command";
    return -EINVAL;
  }

  switch (cmd) {
    case Connect:
    case Disconnect:
    case Show:
    case Stats:
      if (args.begin() == args.end()) {
        *err_msg << "rbd-wvbd: must specify wvbd device or image-or-snap-spec";
        return -EINVAL;
      }
      if (parse_imgpath(*args.begin(), cfg, err_msg) < 0) {
        return -EINVAL;
      }
      args.erase(args.begin());
      break;
    default:
      //shut up gcc;
      break;
  }

  if (args.begin() != args.end()) {
    *err_msg << "rbd-wvbd: unknown args: " << *args.begin();
    return -EINVAL;
  }

  *command = cmd;
  return 0;
}

static int rbd_wvbd(int argc, const char *argv[])
{
  int r;
  Config cfg;
  std::vector<const char*> args;
  argv_to_vec(argc, argv, args);

  // Avoid using dout before calling "do_global_init"
  if (args.empty()) {
    std::cout << argv[0] << ": -h or --help for usage" << std::endl;
    exit(1);
  }

  std::ostringstream err_msg;
  r = parse_args(args, &err_msg, &cmd, &cfg);
  if (r == HELP_INFO) {
    usage();
    return 0;
  } else if (r == VERSION_INFO) {
    std::cout << pretty_version_to_str() << std::endl;
    return 0;
  } else if (r < 0) {
    std::cout << err_msg.str() << std::endl;
    return r;
  }

  auto cct = do_global_init(argc, argv, &cfg);

  switch (cmd) {
    case Connect:
      if (construct_devpath_if_missing(&cfg)) {
        return -EINVAL;
      }
      r = do_map(&cfg);
      if (r < 0)
        return -EINVAL;
      break;
    case Disconnect:
      if (construct_devpath_if_missing(&cfg)) {
        return -EINVAL;
      }
      r = do_unmap(&cfg, true);
      if (r < 0)
        return r;
      break;
    case List:
      r = do_list_mapped_devices(cfg.format, cfg.pretty_format, "");
      if (r < 0)
        return -EINVAL;
      break;
    case Show:
      if (construct_devpath_if_missing(&cfg)) {
        return -EINVAL;
      }
      r = do_list_mapped_devices(cfg.format, cfg.pretty_format, cfg.devpath);
      if (r < 0)
        return -EINVAL;
      break;
    case Service:
    {
      RBDService service;
      // This call will block until the service stops.
      r = RBDService::initialize(&service);
      if (r < 0)
        return -EINVAL;
      break;
    }
    case Stats:
      if (construct_devpath_if_missing(&cfg)) {
        return -EINVAL;
      }
      return do_stats(cfg.devpath);
    default:
      usage();
      break;
  }

  return 0;
}

int main(int argc, const char *argv[])
{
  SetConsoleCtrlHandler(console_handler_routine, true);
  // Avoid the Windows Error Reporting dialog.
  SetErrorMode(GetErrorMode() | SEM_NOGPFAULTERRORBOX);
  // Initialize COM.
  WvbdCoInitializeBasic();
  int r = rbd_wvbd(argc, argv);
  if (r < 0) {
    return r;
  }
  return 0;
}
