/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2019 SUSE LINUX GmbH
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "include/compat.h"

class Win32Service {

public:
  Win32Service(CephContext *cct_);
  virtual ~Win32Service();

  int initialize();
protected:
  void run();
  void shutdown();
  void stop();

  void control_handler(DWORD request);
  void set_status(DWORD current_state, DWORD exit_code = NO_ERROR);

  /* Subclasses should implement the following service hooks. */
  virtual int run_hook();
  /* Invoked when the service is requested to stop. */
  virtual int stop_hook();
  /* Invoked when the system is shutting down. */
  virtual int shutdown_hook();

  CephContext *cct;

private:
  /* A handle used when reporting the current status. */
  SERVICE_STATUS_HANDLE hstatus;
  /* The current service status. */
  SERVICE_STATUS status;
};
