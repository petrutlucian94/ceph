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

class RegistryKey {
public:
  ~RegistryKey();

  static std::optional<RegistryKey> open(
    CephContext *cct, HKEY hRootKey, LPCTSTR strKey, bool create_value);
  static remove(CephContext *cct, HKEY hRootKey, LPCTSTR strKey);

  int flush();

  int set(LPCTSTR lpValue, DWORD data);
  int set(LPCTSTR lpValue, std::string data);

  int get(LPCTSTR lpValue, DWORD* value);
  int get(LPCTSTR lpValue, std::string& value);

  HKEY hKey = NULL;

private:
  RegistryKey(CephContext *cct_, HKEY hKey_): cct(cct_), hkey(hKey_);

  CephContext *cct;
};
