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


// TODO: consider adding a class.
HKEY OpenKey(CephContext *cct, HKEY hRootKey, LPCTSTR strKey, bool create_value);
int DeleteKey(CephContext *cct, HKEY hRootKey, LPCTSTR strKey);
int FlushKey(CephContext *cct, HKEY hKey);
int CloseKey(CephContext *cct, HKEY hKey);
int SetValDword(CephContext *cct, HKEY hKey, LPCTSTR lpValue, DWORD data);
int SetValString(CephContext *cct, HKEY hKey, LPCTSTR lpValue, std::string data);
int GetValDword(CephContext *cct, HKEY hKey, LPCTSTR lpValue, DWORD* value);
int GetValString(CephContext *cct, HKEY hKey, LPCTSTR lpValue, std::string& value);
