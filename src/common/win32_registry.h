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


HKEY OpenKey(HKEY hRootKey, LPCTSTR strKey, bool create_value);
int DeleteKey(HKEY hRootKey, LPCTSTR strKey);
int FlushKey(HKEY hKey);
int CloseKey(HKEY hKey);
int SetValDword(HKEY hKey, LPCTSTR lpValue, DWORD data);
int SetValString(HKEY hKey, LPCTSTR lpValue, std::string data);
int GetValDword(HKEY hKey, LPCTSTR lpValue, DWORD* value);
int GetValString(HKEY hKey, LPCTSTR lpValue, std::string& value);
