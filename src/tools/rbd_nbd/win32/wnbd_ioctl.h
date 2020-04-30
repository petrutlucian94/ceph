/*
 * Copyright (c) 2019 SUSE LLC
 *
 * Licensed under LGPL-2.1 (see LICENSE)
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <winioctl.h>

/* WNBD Defines */
#include "wnbd_shared.h"

#define IOCTL_MINIPORT_PROCESS_SERVICE_IRP CTL_CODE(IOCTL_SCSI_BASE, 0x040e, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

DWORD
WnbdUnmap(PCHAR instanceName);

DWORD
WnbdMap(PCHAR InstanceName,
        PCHAR HostName,
        PCHAR PortName,
        PCHAR ExportName,
        UINT64 DiskSize,
        BOOLEAN Removable);

DWORD
WnbdList(PDISK_INFO_LIST* Output);

#ifdef __cplusplus
}
#endif
