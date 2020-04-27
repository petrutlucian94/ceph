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

#define dout_context cct
#define dout_subsys ceph_subsys_

#include "common/debug.h"
#include "common/errno.h"
#include "common/win32_service.h"


Win32Service::Win32Service(CephContext *cct_): cct(cct_)
{
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwCheckPoint = 0;
    /* The estimated time required for the stop operation in ms. */
    status.dwWaitHint = 0;
}

/* Register service action callbacks */
int Win32Service::initialize()
{
    SERVICE_TABLE_ENTRY service_table[] = {
        {"", (LPSERVICE_MAIN_FUNCTION)run},
        {NULL, NULL}
    };

    /* StartServiceCtrlDispatcher blocks until the service is stopped. */
    if (!StartServiceCtrlDispatcher(service_table)) {
        derr << "StartServiceCtrlDispatcher error: "
             << win32_lasterror_str() << dendl;
        return -EINVAL;
    }
    return 0;
}

void Win32Service::run()
{
    /* Register the control handler. This function is called by the service
     * manager to stop the service. The service name that we're passing here
     * doesn't have to be valid as we're using SERVICE_WIN32_OWN_PROCESS. */
    hstatus = RegisterServiceCtrlHandler("",
        (LPHANDLER_FUNCTION)control_handler);
    if (!hstatus) {
        return;
    }

    set_status(SERVICE_START_PENDING);

    // TODO: should we expect exceptions?
    int err = run_hook();
    if (err) {
        derr << "Failed to start service. Error code: " << err << dendl;
        set_status(SERVICE_STOPPED);
    }
    else {
        set_status(SERVICE_RUNNING);
    }
}

void Win32Service::shutdown()
{
    DWORD original_state = status.dwCurrentState;
    SetServiceStatus(SERVICE_STOP_PENDING);

    int err = shutdown_hook();
    if (err) {
        derr << "Shutdown service hook failed. Error code: " << err << dendl;
        set_status(original_state);
    }
    else {
       set_status(SERVICE_STOPPED);
    }
}

void Win32Service::stop()
{
    DWORD original_state = status.dwCurrentState;
    SetServiceStatus(SERVICE_STOP_PENDING);

    int err = stop_hook();
    if (err) {
        derr << "Service stop hook failed. Error code: " << err << dendl;
        set_status(original_state);
    }
    else {
       set_status(SERVICE_STOPPED);
    }
}

/* This function is registered with the Windows services manager through
 * a call to RegisterServiceCtrlHandler() and will be called by the Windows
 * service manager asynchronously to stop the service. */
void Win32Service::control_handler(DWORD request)
{
    switch (request) {
    case SERVICE_CONTROL_STOP:
        stop();
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        shutdown();
        break;
    default:
        break;
    }
}

void Win32Service::set_status(DWORD current_state, DWORD exit_code = NO_ERROR) {
    static DWORD dwCheckPoint = 1;
    if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED) {
        status.dwCheckPoint = dwCheckPoint++;
    }

    status.dwCurrentState = current_state;
    status.dwWin32ExitCode = exit_code;

    if (hstatus) {
        ::SetServiceStatus(hstatus, &status);
    }
}
