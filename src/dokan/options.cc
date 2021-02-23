static void print_usage() {
  fprintf(stderr, "ceph-dokan.exe\n"
    "  -c CephConfFile  (ex. /r c:\\ceph.conf)\n"
    "  -l DriveLetter (ex. /l m)\n"
    "  -t ThreadCount (ex. /t 5)\n"
    "  -d (enable debug output)\n"
    "  -s (use stderr for output)\n"
    "  -m (use removable drive)\n"
    "  -o (use Windows mount manager)\n"
    "  -c (mount for the current session only)\n"
    "  -w (write-protect drive - read only mount)\n"
    "  -u Uid (use the specified uid when mounting, defaults to 0)\n"
    "  -g Gid (use the specified gid when mounting, defaults to 0)\n"
    "  -n (skip enforcing permissions on client side)\n"
    "  -x sub_mount_path (mount a Ceph filesystem subdirectory)\n"
    "  -h (show this help message)\n"
    "  -i (operation timeout in seconds, defaults to 120)\n"
    );
}

int parse_args(
  std::vector<const char*>& args,
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

  std::vector<const char*>::iterator i;
  std::ostringstream err;
  std::string mountpoint;

  for (i = args.begin(); i != args.end(); ) {
    if (ceph_argparse_flag(args, i, "-h", "--help", (char*)NULL)) {
      *command = Command::Help,
      return 0;
    } else if (ceph_argparse_flag(args, i, "-v", "--version", (char*)NULL)) {
      *command = Command::Version;
    } else if (ceph_argparse_witharg(args, i, &mountpoint, "l", "--mountpoint", (char *)NULL)) {
      cfg->mountpoint = to_wstring(mountpoint);
    } else if (ceph_argparse_witharg(args, i, &cfg->mount_subdir, "x", "--subdir", (char *)NULL)) {
    } else if (ceph_argparse_flag(args, i, "d", "--dokan-debug", (char *)NULL)) {
      cfg->dokan_debug = true;
    } else if (ceph_argparse_flag(args, i, "s", "--dokan-stderr", (char *)NULL)) {
      cfg->dokan_stderr = true;
    } else if (ceph_argparse_flag(args, i, "w", "--read-only", (char *)NULL)) {
      cfg->readonly = true;
    } else if (ceph_argparse_flag(args, i, "w", "--read-only", (char *)NULL)) {
      cfg->readonly = true;
    } else if (ceph_argparse_flag(args, i, "m", "--removable", (char *)NULL)) {
      cfg->removable = true;
    } else if (ceph_argparse_flag(args, i, "o", "--win-mount-mgr", (char *)NULL)) {
      cfg->use_win_mount_mgr = true;
    } else if (ceph_argparse_flag(args, i, "p", "--current-session-only", (char *)NULL)) {
      cfg->current_session_only = true;
    } else if (ceph_argparse_flag(args, i, "n", "--no-acl", (char *)NULL)) {
      cfg->use_acl = false;
    } else if (ceph_argparse_witharg(args, i, (int*)&cfg->uid,
                                     err, "u", "--uid", (char *)NULL)) {
      if (!err.str().empty()) {
        *err_msg << "ceph-dokan: " << err.str();
        return -EINVAL;
      }
      if (cfg->uid < 0) {
        *err_msg << "ceph-dokan: Invalid argument for uid";
        return -EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, (int*)&cfg->gid,
                                     err, "g", "--gid", (char *)NULL)) {
      if (!err.str().empty()) {
        *err_msg << "ceph-dokan: " << err.str();
        return -EINVAL;
      }
      if (cfg->gid < 0) {
        *err_msg << "ceph-dokan: Invalid argument for gid";
        return -EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, (int*)&cfg->thread_count,
                                     err, "t", "--thread-count", (char *)NULL)) {
      if (!err.str().empty()) {
        *err_msg << "ceph-dokan: " << err.str();
        return -EINVAL;
      }
      if (cfg->thread_count < 0) {
        *err_msg << "ceph-dokan: Invalid argument for thread-count";
        return -EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, (int*)&cfg->operation_timeout,
                                     err, "--operation-timeout", (char *)NULL)) {
      if (!err.str().empty()) {
        *err_msg << "ceph-dokan: " << err.str();
        return -EINVAL;
      }
      if (cfg->operation_timeout < 0) {
        *err_msg << "ceph-dokan: Invalid argument for operation-timeout";
        return -EINVAL;
      }
    } else {
      ++i;
    }
  }

  if (cfg->use_win_mount_mgr && cfg->current_session_only) {
    *err_msg << "ceph-dokan: The mount manager always mounts the drive "
             << "for all user sessions.";
    return -EINVAL;
  }

  Command cmd = Command::None;
  if (args.begin() != args.end()) {
    if (strcmp(*args.begin(), "help") == 0) {
      cmd = Command::Help;
    } else if (strcmp(*args.begin(), "version") == 0) {
      cmd = Command::Version;
    } else if (strcmp(*args.begin(), "map") == 0) {
      cmd = Command::Map;
    } else {
      *err_msg << "ceph-dokan: unknown command: " <<  *args.begin();
      return -EINVAL;
    }
    args.erase(args.begin());
  }

  if (cmd == None) {
    // The default command.
    cmd = Command::Map;
  }
  else {
    // Remove explicit command.
    args.erase(args.begin());
  }

  switch (cmd) {
    case Map:
      if (cfg->mountpoint.empty) {
        *err_msg << "ceph-dokan: missing mountpoint.";
        return -EINVAL;
      }
      break;
    default:
      break;
  }

  if (args.begin() != args.end()) {
    *err_msg << "ceph-dokan: unknown args: " << *args.begin();
    return -EINVAL;
  }

  *command = cmd;
  return 0;
}

int set_dokan_options(Config *cfg, PDOKAN_OPTIONS dokan_options) {
  ZeroMemory(dokan_options, sizeof(DOKAN_OPTIONS));
  dokan_options->Version = DOKAN_VERSION;
  dokan_options->ThreadCount = cfg->thread_count;
  dokan_options->MountPoint = cfg->mountpoint.c_str();
  dokan_options->Timeout = cfg->operation_timeout * 1000;

  if (cfg->removable)
    dokan_options->Options |= DOKAN_OPTION_REMOVABLE;
  if (cfg->use_win_mount_mgr)
    dokan_options->Options |= DOKAN_OPTION_MOUNT_MANAGER;
  if (cfg->current_session_only)
    dokan_options->Options |= DOKAN_OPTION_CURRENT_SESSION;
  if (cfg->readonly)
    dokan_options->Options |= DOKAN_OPTION_WRITE_PROTECT;
  if (cfg->dokan_debug)
    dokan_options->Options |= DOKAN_OPTION_DEBUG;
  if (cfg->dokan_stderr)
    dokan_options->Options |= DOKAN_OPTION_STDERR;

  return 0;
}