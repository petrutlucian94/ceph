// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (c) 2020 SUSE LLC
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#ifndef _DIRENT_H
#define _DIRENT_H       1

/*
 * File types
 */
#define DT_UNKNOWN   0
#define DT_FIFO      1
#define DT_CHR       2
#define DT_DIR       4
#define DT_BLK       6
#define DT_REG       8
#define DT_LNK      10
#define DT_SOCK     12
#define DT_WHT      14

// Windows stat types:
// S_IFIFO 0x1000
// S_IFCHR 0x2000
// S_IFDIR 0x4000
// S_IFREG 0x8000

/*
 * Convert between stat structure types and directory types.
 */
#define IFTODT(mode)    (((mode) & 0170000) >> 12)
// #define DTTOIF(dirtype) ((dirtype) << 12)

// TODO: handle symlinks and unix sockets.
// Windows reports symlinks as regular files, so we may need some extra
// checks if we want to support symlinks. Plus, it requires privileged rights
// when creating symlinks.
#define DTTOIF(dirtype)     \
    (dirtype == S_IFIFO) || \
    (dirtype == S_IFCHR) || \
    (dirtype == S_IFDIR) || \
    (dirtype == S_IFREG)  ? \
        dirtype << 12     : \
        0

struct dirent {
  char d_name[_MAX_PATH]; /* filename */
};

typedef struct {
  HANDLE      handle;
  BOOL        firstread;
  WIN32_FIND_DATA data;
  struct dirent entry;
} DIR;

#ifdef __cplusplus
extern "C" {
#endif

DIR* opendir(const char* name);

struct dirent* readdir(DIR* dirp);

int closedir(DIR* dirp);

#ifdef __cplusplus
}
#endif

#endif /* _DIRENT_H */
