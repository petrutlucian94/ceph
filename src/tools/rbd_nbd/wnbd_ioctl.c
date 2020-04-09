/*
 * Copyright (c) 2019 SUSE LLC
 *
 * Licensed under LGPL-2.1 (see LICENSE)
 */

#include "wnbd_ioctl.h"

void GLAToString()
{
    LPVOID LpMsgBuf;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        0,
        (LPTSTR)&LpMsgBuf,
        0,
        NULL
    );

    fprintf(stderr, "GetLastError: %s", (LPTSTR)LpMsgBuf);

    LocalFree(LpMsgBuf);
}

HANDLE
GetWnbdDriverHandle(VOID)
{
    HDEVINFO DevInfo = { 0 };
    SP_DEVICE_INTERFACE_DATA DevInterfaceData = { 0 };
    PSP_DEVICE_INTERFACE_DETAIL_DATA DevInterfaceDetailData = NULL;
    ULONG DevIndex = { 0 };
    ULONG RequiredSize = { 0 };
    ULONG GLA = { 0 };
    HANDLE WnbdDriverHandle = { 0 };
    DWORD BytesReturned = { 0 };
    USER_COMMAND Command = { 0 };
    BOOL DevStatus = { 0 };

    DevInfo = SetupDiGetClassDevs(&WNBD_GUID, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (DevInfo == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "SetupDiGetClassDevs failed with error 0x%lx\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    DevInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    DevIndex = 0;

    while (SetupDiEnumDeviceInterfaces(DevInfo, NULL, &WNBD_GUID, DevIndex++, &DevInterfaceData)) {
        if (DevInterfaceDetailData != NULL) {
            free(DevInterfaceDetailData);
            DevInterfaceDetailData = NULL;
        }

        if (!SetupDiGetDeviceInterfaceDetail(DevInfo, &DevInterfaceData, NULL, 0, &RequiredSize, NULL)) {
            GLA = GetLastError();

            if (GLA != ERROR_INSUFFICIENT_BUFFER) {
                fprintf(stderr, "SetupDiGetDeviceInterfaceDetail failed with error 0x%lx\n", GLA);
                SetupDiDestroyDeviceInfoList(DevInfo);
                return INVALID_HANDLE_VALUE;
            }
        }

        DevInterfaceDetailData =
            (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(RequiredSize);

        if (!DevInterfaceDetailData) {
            fprintf(stderr, "Unable to allocate resources\n");
            SetupDiDestroyDeviceInfoList(DevInfo);
            return INVALID_HANDLE_VALUE;
        }

        DevInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);


        if (!SetupDiGetDeviceInterfaceDetail(DevInfo, &DevInterfaceData, DevInterfaceDetailData,
            RequiredSize, &RequiredSize, NULL)) {
            fprintf(stderr, "SetupDiGetDeviceInterfaceDetail failed with error 0x%lx\n", GetLastError());
            SetupDiDestroyDeviceInfoList(DevInfo);
            free(DevInterfaceDetailData);
            return INVALID_HANDLE_VALUE;
        }

        WnbdDriverHandle = CreateFile(DevInterfaceDetailData->DevicePath,
            GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED, 0);

        Command.IoCode = IOCTL_WNBDVM_PORT;

        DevStatus = DeviceIoControl(WnbdDriverHandle, IOCTL_MINIPORT_PROCESS_SERVICE_IRP,
            &Command, sizeof(Command), &Command, sizeof(Command), &BytesReturned, NULL);

        if (!DevStatus) {
            DWORD error = GetLastError();
            fprintf(stderr, "Failed sending NOOP command IOCTL_MINIPORT_PROCESS_SERVICE_IRP\n");
            fprintf(stderr, "\\\\.\\SCSI%s: error:%lu.\n", DevInterfaceDetailData->DevicePath, error);
            CloseHandle(WnbdDriverHandle);
            WnbdDriverHandle = INVALID_HANDLE_VALUE;
            GLAToString();
            continue;
        } else {
            SetupDiDestroyDeviceInfoList(DevInfo);
            free(DevInterfaceDetailData);
            return WnbdDriverHandle;
        }
    }

    GLA = GetLastError();

    if (GLA != ERROR_NO_MORE_ITEMS) {
        fprintf(stderr, "SetupDiGetDeviceInterfaceDetail failed with error 0x%lx\n", GLA);
        SetupDiDestroyDeviceInfoList(DevInfo);
        free(DevInterfaceDetailData);
        return INVALID_HANDLE_VALUE;
    }

    SetupDiDestroyDeviceInfoList(DevInfo);

    if (DevInterfaceDetailData == NULL) {
        fprintf(stderr, "Unable to find any Nothing devices!\n");
        return INVALID_HANDLE_VALUE;
    }
    return INVALID_HANDLE_VALUE;

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

    WnbdDriverHandle = GetWnbdDriverHandle();
    if (WnbdDriverHandle == INVALID_HANDLE_VALUE) {
        Status = GetLastError();
        fprintf(stderr, "Could not get WNBD driver handle. Can not send requests.\n");
        fprintf(stderr, "The driver maybe is not installed\n");
        GLAToString();
        goto Exit;
    }

    memcpy(&ConnectIn.InstanceName, InstanceName, min(strlen(InstanceName)+1, MAX_NAME_LENGTH));
    memcpy(&ConnectIn.Hostname, HostName, min(strlen(HostName)+1, MAX_NAME_LENGTH));
    memcpy(&ConnectIn.PortName, PortName, min(strlen(PortName)+1, MAX_NAME_LENGTH));
    memcpy(&ConnectIn.ExportName, ExportName, min(strlen(ExportName)+1, MAX_NAME_LENGTH));
    memcpy(&ConnectIn.SerialNumber, InstanceName, min(strlen(InstanceName)+1, MAX_NAME_LENGTH));
    ConnectIn.DiskSize = DiskSize;
    ConnectIn.IoControlCode = IOCTL_WNBDVM_MAP;
    ConnectIn.Pid = Pid;
    ConnectIn.MustNegotiate = MustNegotiate;
    ConnectIn.BlockSize = 0;

    DevStatus = DeviceIoControl(WnbdDriverHandle, IOCTL_MINIPORT_PROCESS_SERVICE_IRP, &ConnectIn, sizeof(USER_IN),
        NULL, 0, &BytesReturned, NULL);

    if (!DevStatus) {
        Status = GetLastError();
        fprintf(stderr, "IOCTL_MINIPORT_PROCESS_SERVICE_IRP failed\n");
        GLAToString();
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

    WnbdDriverHandle = GetWnbdDriverHandle();
    if (WnbdDriverHandle == INVALID_HANDLE_VALUE) {
        Status = GetLastError();
        fprintf(stderr, "Could not get WNBD driver handle. Can not send requests.\n");
        fprintf(stderr, "The driver maybe is not installed\n");
        GLAToString();
        goto Exit;
    }

    memcpy(&DisconnectIn.InstanceName[0], InstanceName, min(strlen(InstanceName), MAX_NAME_LENGTH));
    DisconnectIn.IoControlCode = IOCTL_WNBDVM_UNMAP;

    DevStatus = DeviceIoControl(WnbdDriverHandle, IOCTL_MINIPORT_PROCESS_SERVICE_IRP,
        &DisconnectIn, sizeof(USER_IN), NULL, 0, &BytesReturned, NULL);

    if (!DevStatus) {
        Status = GetLastError();
        fprintf(stderr, "IOCTL_MINIPORT_PROCESS_SERVICE_IRP failed\n");
        GLAToString();
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
        Status = GetLastError();
        fprintf(stderr, "Could not get WNBD driver handle. Can not send requests.\n");
        fprintf(stderr, "The driver maybe is not installed\n");
        GLAToString("wnbd-client");
        goto Exit;
    }

    Buffer = malloc(65000);
    if (!Buffer) {
        CloseHandle(WnbdDriverHandle);
        Status = ERROR_NOT_ENOUGH_MEMORY;
    }
    memset(Buffer, 0, 65000);
    Command.IoCode = IOCTL_WNBDVM_LIST;

    DevStatus = DeviceIoControl(WnbdDriverHandle, IOCTL_MINIPORT_PROCESS_SERVICE_IRP,
        &Command, sizeof(Command), Buffer, 65000, &BytesReturned, NULL);

    if (!DevStatus) {
        Status = GetLastError();
        fprintf(stderr, "IOCTL_MINIPORT_PROCESS_SERVICE_IRP failed\n");
        GLAToString();
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
