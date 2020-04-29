/*
 * Copyright (c) 2019 SUSE LLC
 *
 * Licensed under LGPL-2.1 (see LICENSE)
 */

#include "windefs.h"
#include <windows.h>

#include "wnbd_ioctl.h"

#include <ntddscsi.h>
#include <setupapi.h>
#include <string.h>
#include <process.h>

#include "common/debug.h"
#include "common/errno.h"

#include "global/global_context.h"

#define STRING_OVERFLOWS(Str, MaxLen) strlen(Str + 1) > MaxLen

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rbd


HANDLE
GetWnbdDriverHandle()
{
  HDEVINFO DevInfo = { 0 };
  SP_DEVICE_INTERFACE_DATA DevInterfaceData = { 0 };
  PSP_DEVICE_INTERFACE_DETAIL_DATA DevInterfaceDetailData = NULL;
  ULONG DevIndex = 0;
  ULONG RequiredSize = 0;
  ULONG ErrorCode = 0;
  HANDLE WnbdDriverHandle = INVALID_HANDLE_VALUE;
  DWORD BytesReturned = 0;
  USER_COMMAND Command = { 0 };
  BOOL DevStatus = 0;

  DevInfo = SetupDiGetClassDevs(&WNBD_GUID, NULL, NULL,
                                DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (DevInfo == INVALID_HANDLE_VALUE) {
    derr << "SetupDiGetClassDevs failed. Error: " << GetLastError() << dendl;
    goto Exit;
  }

  DevInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
  DevIndex = 0;

  while (SetupDiEnumDeviceInterfaces(DevInfo, NULL, &WNBD_GUID,
                                     DevIndex++, &DevInterfaceData)) {
    if (!SetupDiGetDeviceInterfaceDetail(DevInfo, &DevInterfaceData, NULL,
                                         0, &RequiredSize, NULL)) {
      ErrorCode = GetLastError();
      if (ERROR_INSUFFICIENT_BUFFER != ErrorCode) {
        derr << "SetupDiGetDeviceInterfaceDetail failed. Error: "
             << ErrorCode << dendl;
        goto Exit;
      }
    }

    DevInterfaceDetailData =
      (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(RequiredSize);

    if (!DevInterfaceDetailData) {
      derr << "Unable to allocate resources." << dendl;
      goto Exit;
    }

    DevInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

    if (!SetupDiGetDeviceInterfaceDetail(
          DevInfo, &DevInterfaceData, DevInterfaceDetailData,
          RequiredSize, &RequiredSize, NULL)) {
      derr << "SetupDiGetDeviceInterfaceDetail failed. Error: "
           << GetLastError() << dendl;
      goto Exit;
    }

    WnbdDriverHandle = CreateFile(
      DevInterfaceDetailData->DevicePath,
      GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING,
      FILE_FLAG_OVERLAPPED, 0);

    Command.IoCode = IOCTL_WNBDVM_PORT;

    DevStatus = DeviceIoControl(
      WnbdDriverHandle, IOCTL_MINIPORT_PROCESS_SERVICE_IRP, &Command,
      sizeof(Command), &Command, sizeof(Command), &BytesReturned, NULL);

    if (!DevStatus) {
      ErrorCode = GetLastError();
      derr << "Failed sending NOOP command IOCTL_MINIPORT_PROCESS_SERVICE_IRP "
           << "to \\\\.\\SCSI" << DevInterfaceDetailData->DevicePath
           << ". Error: " << ErrorCode << dendl;
      CloseHandle(WnbdDriverHandle);
      WnbdDriverHandle = INVALID_HANDLE_VALUE;
      continue;
    } else {
      goto Exit;
    }
  }

  ErrorCode = GetLastError();
  if (ErrorCode != ERROR_NO_MORE_ITEMS) {
    derr << "SetupDiGetDeviceInterfaceDetail failed. Error: "
         << ErrorCode << dendl;
    goto Exit;
  }

  if (DevInterfaceDetailData == NULL) {
    derr << "Could not find any devices!" << dendl;
  }

Exit:
  if (DevInterfaceDetailData) {
    free(DevInterfaceDetailData);
  }
  if (DevInfo) {
    SetupDiDestroyDeviceInfoList(DevInfo);
  }

  if (WnbdDriverHandle == INVALID_HANDLE_VALUE) {
    derr << "Could not get WNBD driver handle. Can not send requests. "
         << "Make sure that the driver is installed." << dendl;
  }

  return WnbdDriverHandle;
}

DWORD
WnbdMap(PCHAR InstanceName,
        PCHAR HostName,
        PCHAR PortName,
        PCHAR ExportName,
        UINT64 DiskSize,
        BOOLEAN MustNegotiate)
{
  USER_IN ConnectIn = { 0 };
  HANDLE WnbdDriverHandle = INVALID_HANDLE_VALUE;
  DWORD Status = ERROR_SUCCESS;
  DWORD BytesReturned = 0;
  BOOL DevStatus = 0;
  INT Pid = getpid();

  if(STRING_OVERFLOWS(InstanceName, MAX_NAME_LENGTH) ||
      STRING_OVERFLOWS(HostName, MAX_NAME_LENGTH) ||
      STRING_OVERFLOWS(PortName, MAX_NAME_LENGTH) ||
      STRING_OVERFLOWS(ExportName, MAX_NAME_LENGTH)) {
    return ERROR_BUFFER_OVERFLOW;
  }

  WnbdDriverHandle = GetWnbdDriverHandle();
  if (WnbdDriverHandle == INVALID_HANDLE_VALUE) {
    Status = ERROR_INVALID_HANDLE;
    goto Exit;
  }

  memcpy(&ConnectIn.InstanceName, InstanceName, strlen(InstanceName) + 1);
  memcpy(&ConnectIn.Hostname, HostName, strlen(HostName) + 1);
  memcpy(&ConnectIn.PortName, PortName, strlen(PortName) + 1);
  memcpy(&ConnectIn.ExportName, ExportName, strlen(ExportName) + 1);
  memcpy(&ConnectIn.SerialNumber, InstanceName, strlen(InstanceName) + 1);
  ConnectIn.DiskSize = DiskSize;
  ConnectIn.IoControlCode = IOCTL_WNBDVM_MAP;
  ConnectIn.Pid = Pid;
  ConnectIn.MustNegotiate = MustNegotiate;
  ConnectIn.BlockSize = 0;

  DevStatus = DeviceIoControl(
    WnbdDriverHandle, IOCTL_MINIPORT_PROCESS_SERVICE_IRP,
    &ConnectIn, sizeof(USER_IN), NULL, 0, &BytesReturned, NULL);

  if (!DevStatus) {
    Status = GetLastError();
    derr << "IOCTL_MINIPORT_PROCESS_SERVICE_IRP IOCTL_WNBDVM_MAP failed."
         << " Error: " << Status << dendl;
  }

  CloseHandle(WnbdDriverHandle);
Exit:
  return Status;
}

DWORD
WnbdUnmap(PCHAR InstanceName)
{
  USER_IN DisconnectIn = { 0 };
  HANDLE WnbdDriverHandle = INVALID_HANDLE_VALUE;
  DWORD Status = ERROR_SUCCESS;
  DWORD BytesReturned = 0;
  BOOL DevStatus = FALSE;

  if(STRING_OVERFLOWS(InstanceName, MAX_NAME_LENGTH)) {
    return ERROR_BUFFER_OVERFLOW;
  }

  WnbdDriverHandle = GetWnbdDriverHandle();
  if (WnbdDriverHandle == INVALID_HANDLE_VALUE) {
    Status = ERROR_INVALID_HANDLE;
    goto Exit;
  }

  memcpy(&DisconnectIn.InstanceName[0], InstanceName, strlen(InstanceName));
  DisconnectIn.IoControlCode = IOCTL_WNBDVM_UNMAP;

  DevStatus = DeviceIoControl(
    WnbdDriverHandle, IOCTL_MINIPORT_PROCESS_SERVICE_IRP,
    &DisconnectIn, sizeof(USER_IN), NULL, 0, &BytesReturned, NULL);

  if (!DevStatus) {
    Status = GetLastError();
    derr << "IOCTL_MINIPORT_PROCESS_SERVICE_IRP IOCTL_WNBDVM_UNMAP failed."
         << " Error: " << Status << dendl;
  }

  CloseHandle(WnbdDriverHandle);
Exit:
  return Status;
}

DWORD
WnbdList(PGET_LIST_OUT* Output)
{
  HANDLE WnbdDriverHandle = INVALID_HANDLE_VALUE;
  DWORD Status = ERROR_SUCCESS;
  DWORD BytesReturned = 0;
  PUCHAR Buffer = NULL;
  USER_COMMAND Command = { 0 };
  BOOL DevStatus = FALSE;

  WnbdDriverHandle = GetWnbdDriverHandle();
  if (WnbdDriverHandle == INVALID_HANDLE_VALUE) {
    Status = ERROR_INVALID_HANDLE;
    goto Exit;
  }

  // TODO: handle the situation in which the buffer is too small.
  // Make sure that the driver returns the right error code.
  Buffer = malloc(65000);
  if (!Buffer) {
    CloseHandle(WnbdDriverHandle);
    Status = ERROR_NOT_ENOUGH_MEMORY;
  }
  memset(Buffer, 0, 65000);
  Command.IoCode = IOCTL_WNBDVM_LIST;

  DevStatus = DeviceIoControl(
    WnbdDriverHandle, IOCTL_MINIPORT_PROCESS_SERVICE_IRP,
    &Command, sizeof(Command), Buffer, 65000, &BytesReturned, NULL);

  if (!DevStatus) {
    Status = GetLastError();
    derr << "IOCTL_MINIPORT_PROCESS_SERVICE_IRP IOCTL_WNBDVM_LIST failed."
         << " Error: " << Status << dendl;
  }

  PGET_LIST_OUT ActiveConnectList = (PGET_LIST_OUT)Buffer;

  if (Buffer && BytesReturned && ActiveConnectList->ActiveListCount) {
    Status = ERROR_SUCCESS;
  }
  if (ERROR_SUCCESS != Status) {
    free(Buffer);
    Buffer = NULL;
  }
  *Output = (PGET_LIST_OUT)Buffer;
Exit:
  return Status;
}
