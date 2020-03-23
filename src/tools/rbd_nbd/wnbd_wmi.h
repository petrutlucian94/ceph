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
#include <iostream>

struct DiskInfo
{
    std::wstring deviceId;
    std::wstring freeSpace;
    uint32_t Index;
};


struct Win32_Proc
{
    std::wstring CommandLine;
    uint32_t process;
};

bool ReleaseWMI();
bool InitWMI();
std::wstring GetProperty(IWbemClassObject* pclsObj, const std::wstring& property);
UINT32 GetPropertyInt(IWbemClassObject* pclsObj, const std::wstring& property);
bool QueryWMI(BSTR Query, std::vector<Win32_Proc>& proc);
bool QueryWMI(BSTR Query, std::vector<DiskInfo>& disks);
