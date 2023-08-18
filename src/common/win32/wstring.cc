/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2022 Cloudbase Solutions
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "wstring.h"

#include <boost/locale/encoding_utf.hpp>

#include <windows.h>
#include <shellapi.h>

#include "common/errno.h"

using boost::locale::conv::utf_to_utf;

std::wstring to_wstring(const std::string& str)
{
  return utf_to_utf<wchar_t>(str.c_str(), str.c_str() + str.size());
}

std::string to_string(const std::wstring& str)
{
  return utf_to_utf<char>(str.c_str(), str.c_str() + str.size());
}

// The Windows "main" function receives ANSI encoded arguments while
// "wmain" uses UTF-16. This function retrieves the command line in UTF-8.
char** get_utf8_argv()
{
  LPWSTR cmdline = GetCommandLineW();
  int argc;

  LPWSTR* argv_w = CommandLineToArgvW(cmdline, &argc);
  if (!argv_w) {
    return nullptr;
  }

  size_t buff_sz = sizeof(void*) * argc;
  for (int i=0; i<argc; i++) {
    buff_sz += wcslen(argv_w[i]) * sizeof(wchar_t) + 1;
  }

  char** buff = (char**) calloc(1, buff_sz);
  if (!buff) {
    return nullptr;
  }

  char* curr_arg = (char*) buff + sizeof(void*) * argc;
  for (int i=0; i<argc; i++) {
    buff[i] = curr_arg;
    std::string str_arg = to_string(argv_w[i]);
    size_t curr_arg_sz = str_arg.size() + 1;
    str_arg.copy(curr_arg, curr_arg_sz);
    curr_arg += curr_arg_sz;
  }

  return buff;
}
