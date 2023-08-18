// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "tools/rbd/Shell.h"

#ifdef _WIN32

#include <iostream>

#include "common/win32/wstring.h"

int main(int argc, const char **argv)
{
  setlocale(LC_ALL, ".UTF8");
  SetConsoleOutputCP(CP_UTF8);
  char** argv_utf8 = get_utf8_argv();
  if (!argv_utf8) {
    std::cerr << "Couldn't convert args to utf8." << std::endl;
    return -EINVAL;
  }

  rbd::Shell shell;
  return shell.execute(argc, (const char**) argv_utf8);
}

#else
int main(int argc, const char **argv)
{
  rbd::Shell shell;
  return shell.execute(argc, argv);
}
#endif
