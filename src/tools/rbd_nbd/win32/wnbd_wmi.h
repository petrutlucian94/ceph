/*
 * Copyright (c) 2019 SUSE LLC
 *
 * Licensed under LGPL-2.1 (see LICENSE)
 */

#pragma once
#define _WIN32_DCOM
#include <wbemcli.h>

#include <string>
#include <vector>

struct DiskInfo
{
  std::wstring deviceId;
  std::wstring freeSpace;
  uint32_t Index;
};

bool ReleaseWMI();
bool InitWMI();
std::wstring GetProperty(IWbemClassObject* pclsObj,
                         const std::wstring& property);
UINT32 GetPropertyInt(IWbemClassObject* pclsObj,
                      const std::wstring& property);

bool GetDiskDrives(BSTR Query, std::vector<DiskInfo>& disks);
bool GetDiskDrivesBySerialNumber(std::wstring serialNumber,
                                 std::vector<DiskInfo>& disks);
int GetDiskNumberBySerialNumber(std::wstring serialNumber);
