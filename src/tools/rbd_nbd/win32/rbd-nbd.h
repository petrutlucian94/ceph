/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2020 SUSE LINUX GmbH
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <string.h>
#include <iostream>
#include <vector>

#include "include/compat.h"
#include "common/win32/registry.h"

#include "wnbd_shared.h"

#define SERVICE_REG_KEY "SYSTEM\\CurrentControlSet\\Services\\rbd-nbd"

#define WNBD_STATUS_CONNECTED "connected"
#define WNBD_STATUS_DISCONNECTED "disconnected"

#define RBD_NBD_BLKSIZE 512UL

#define HELP_INFO 1
#define VERSION_INFO 2


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

  // TODO: consider moving those fields to a separate structure. Those
  // provide mapping information without actually being configurable.
  // The disk number is provided by Windows.
  int disk_number = -1;
  int pid = 0;
  std::string serial_number;
  bool connected = false;
  bool wnbd_mapped = false;
  std::string command_line;
  std::string admin_sock_path;
};

enum Command {
  None,
  Connect,
  Disconnect,
  List,
  Show,
  Service,
  Stats
};

std::wstring to_wstring(const std::string& str);
std::string to_string(const std::wstring& str);
bool is_process_running(DWORD pid);

void daemonize_complete(HANDLE parent_pipe);
void unmap_at_exit();

int disconnect_all_mappings(bool unregister);
int restart_registered_mappings();
bool map_device_using_suprocess(std::string command_line);

std::string get_device_name_per_pid(int pid);
int initialize_wnbd_connection(Config* cfg, uint64_t size,
                               uint64_t nbd_flags);

int construct_devpath_if_missing(Config* cfg);
int save_config_to_registry(Config* cfg);
int remove_config_from_registry(Config* cfg);
int load_mapping_config_from_registry(char* devpath, Config* cfg);

BOOL WINAPI console_handler_routine(DWORD dwCtrlType);

static int parse_args(std::vector<const char*>& args,
                      std::ostream *err_msg,
                      Command *command, Config *cfg);
static int do_unmap(Config *cfg, bool unregister);


class BaseIterator {
  public:
    virtual ~BaseIterator() {};
    virtual bool get(Config *cfg) = 0;

    int get_error() {
      return error;
    }
  protected:
    int error = 0;
    int index = -1;
};


// Iterate over mapped devices, retrieving info from the WNBD driver.
class WNBDActiveDiskIterator : public BaseIterator {
  public:
    WNBDActiveDiskIterator();
    ~WNBDActiveDiskIterator();

    bool get(Config *cfg);

  private:
    PDISK_INFO_LIST disk_list = NULL;
};

// Iterate over the Windows registry key, retrieving registered mappings.
class RegistryDiskIterator : public BaseIterator {
  public:
    RegistryDiskIterator();
    ~RegistryDiskIterator() {
      delete reg_key;
    }

    bool get(Config *cfg);
  private:
    DWORD subkey_count = 0;
    char subkey_name[MAX_PATH];

  RegistryKey* reg_key = NULL;
};

// Iterate over all RBD mappings, getting info from the registry and WNBD.
class WNBDDiskIterator : public BaseIterator {
  public:
    bool get(Config *cfg);

  private:
    // We'll keep track of the active devices.
    std::set<std::string> active_devices;

    WNBDActiveDiskIterator active_iterator;
    RegistryDiskIterator registry_iterator;
};
