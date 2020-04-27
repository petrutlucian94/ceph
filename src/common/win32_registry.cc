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

#include "common/debug.h"
#include "common/errno.h"
#include "common/win32_registry.h"

#define dout_subsys ceph_subsys_


HKEY OpenKey(HKEY hRootKey, LPCTSTR strKey, bool create_value)
{
    HKEY hKey = NULL;
    DWORD status = RegOpenKeyEx(hRootKey, strKey, 0, KEY_ALL_ACCESS, &hKey);

    if (status == ERROR_FILE_NOT_FOUND && create_value)
    {
        dout(10) << "Creating registry key: " << strKey << dendl;
        status = RegCreateKeyEx(
            hRootKey, strKey, 0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS, NULL, &hKey, NULL);
    }

    if (ERROR_SUCCESS != status) {
        derr << "Error: " << win32_strerror(status)
             << ". Could not open registry key: " << strKey << dendl;
    }

    return hKey;
}

int DeleteKey(HKEY hRootKey, LPCTSTR strKey)
{
    DWORD status = RegDeleteKeyEx(hRootKey, strKey, KEY_WOW64_64KEY, 0);

    if (status == ERROR_FILE_NOT_FOUND)
    {
        dout(20) << "Registry key : " << strKey << " does not exist."<< dendl;
        return 0;
    }

    if (ERROR_SUCCESS != status) {
        derr << "Error: " << win32_strerror(status)
             << ". Could not delete registry key: " << strKey << dendl;
        return -EINVAL;
    }

    return 0;
}

int FlushKey(HKEY hKey) {
    DWORD status = RegFlushKey(hKey);
    if (ERROR_SUCCESS != status) {
        derr << "Error: " << win32_strerror(status)
             << ". Could not flush registry key." << dendl;
        return -EINVAL;
    }

    return 0;
}

int CloseKey(HKEY hKey) {
    DWORD status = RegCloseKey(hKey);
    if (ERROR_SUCCESS != status) {
        derr << "Error: " << win32_strerror(status)
             << ". Could not close registry key." << dendl;
        return -EINVAL;
    }

    return 0;
}

int SetValDword(HKEY hKey, LPCTSTR lpValue, DWORD data)
{
    DWORD status = RegSetValueEx(hKey, lpValue, 0, REG_DWORD,
                                 (LPBYTE)&data, sizeof(DWORD));
    if (ERROR_SUCCESS != status) {
        derr << "Error: " << win32_strerror(status)
             << ". Could not set registry value: " << (char*)lpValue << dendl;
        return -EINVAL;
    }

    return 0;
}

int SetValString(HKEY hKey, LPCTSTR lpValue, std::string data)
{
    DWORD status = RegSetValueEx(hKey, lpValue, 0, REG_SZ,
                                 (LPBYTE)data.c_str(), data.length());
    if (ERROR_SUCCESS != status) {
        derr << "Error: " << win32_strerror(status)
             << ". Could not set registry value: " << (char*)lpValue << dendl;
        return -EINVAL;
    }

    return 0;
}

int GetValDword(HKEY hKey, LPCTSTR lpValue, DWORD* value)
{
    DWORD data;
    DWORD size = sizeof(data);
    DWORD type = REG_DWORD;
    DWORD status = RegQueryValueEx(hKey, lpValue, NULL,
                                   &type, (LPBYTE)&data, &size);
    if (ERROR_SUCCESS != status) {
        derr << "Error: " << win32_strerror(status)
             << ". Could not set registry value: " << (char*)lpValue << dendl;
        return -EINVAL;
    }
    *value = data;

    return 0;
}

int GetValString(HKEY hKey, LPCTSTR lpValue, std::string& value)
{
    std::string data{""};
    DWORD size = 0;
    DWORD type = REG_SZ;
    DWORD status = RegQueryValueEx(hKey, lpValue, NULL, &type,
                                   (LPBYTE)data.c_str(), &size);
    if (ERROR_MORE_DATA == status) {
        data.resize(size);
        status = RegQueryValueEx(hKey, lpValue, NULL, &type,
                                 (LPBYTE)data.c_str(), &size);
    }
    
    if (ERROR_SUCCESS != status) {
        derr << "Error: " << win32_strerror(status)
             << ". Could not set registry value: " << (char*)lpValue << dendl;
        return -EINVAL;
    }
    value.assign(data.c_str());

    return 0;
}
