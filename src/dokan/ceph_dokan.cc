/*
 * ceph-dokan - Win32 CephFS client based on Dokan
 *
 * Copyright (C) 2021 SUSE LINUX GmbH
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
*/

#define UNICODE
#define _UNICODE

#include "include/compat.h"
#include "include/cephfs/libcephfs.h"

#include "ceph_dokan.h"

#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <fileinfo.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sddl.h>
#include <accctrl.h>
#include <aclapi.h>
#include <ntstatus.h>

#include "common/ceph_argparse.h"
#include "common/config.h"
#include "common/debug.h"
#include "common/dout.h"
#include "common/errno.h"
#include "common/version.h"

#include "global/global_init.h"

#include "dbg.h"
#include "posix_acl.h"
#include "utils.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_client
#undef dout_prefix
#define dout_prefix *_dout << "ceph-dokan: "

using namespace std;

#define MAX_PATH_CEPH 8192

#define READ_ACCESS_REQUESTED(access_mode) \
    (access_mode & GENERIC_READ || \
     access_mode & FILE_SHARE_READ || \
     access_mode & STANDARD_RIGHTS_READ || \
     access_mode & FILE_SHARE_READ)
#define WRITE_ACCESS_REQUESTED(access_mode) \
    (access_mode & GENERIC_WRITE || \
     access_mode & FILE_SHARE_WRITE || \
     access_mode & STANDARD_RIGHTS_WRITE || \
     access_mode & FILE_SHARE_WRITE)

struct ceph_mount_info *cmount;
Config *g_cfg;

// Used as part of DOKAN_FILE_INFO.Context, must fit within 8B.
typedef struct {
  int   fd;
  short read_only;
} fd_context, *pfd_context;
static_assert(sizeof(fd_context) <= 8,
              "fd_context exceeds DOKAN_FILE_INFO.Context size.");

static void
GetFilePath(
  PWCHAR  filePath,
  ULONG  numberOfElements,
  LPCWSTR FileName)
{
  RtlZeroMemory(filePath, numberOfElements * sizeof(WCHAR));
  wcsncat(filePath, FileName, wcslen(FileName));
}

string get_path(LPCWSTR path_w) {
  string path = to_string(path_w);
  replace(path.begin(), path.end(), '\\', '/');
  return path;
}

static NTSTATUS WinCephCreateDirectory(
  LPCWSTR FileName,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  string file_name = get_path(FileName);
  dout(20) << __func__ << " " << file_name << dendl;
  if (file_name == "/") {
    return 0;
  }

  if (check_parent_perm(file_name, PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
    return STATUS_ACCESS_DENIED;

  int ret = ceph_mkdir(cmount, file_name.c_str(), 0755);
  if (ret < 0) {
    dout(10) << __func__ << " " << file_name << " ceph_mkdir failed. Error: " << ret << dendl;
    return errno_to_ntstatus(ret);
  }

  ceph_chown(cmount, file_name.c_str(), g_cfg->uid, g_cfg->gid);
  fuse_init_acl(cmount, file_name.c_str(), 0040777); // S_IRWXU|S_IRWXG|S_IRWXO|S_IFDIR
  return 0;
}

static int WinCephOpenDirectory(
  LPCWSTR FileName,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  string file_name = get_path(FileName);
  dout(20) << __func__ << " " << file_name << dendl;

  struct ceph_statx stbuf;
  unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
  int ret = ceph_statx(cmount, file_name.c_str(), &stbuf, requested_attrs, 0);
  if (ret) {
    dout(10) << __func__ << " " << file_name << ": ceph_statx failed. Error: " << ret << dendl;
    return errno_to_ntstatus(ret);
  }

  if (check_perm(file_name, PERM_WALK_CHECK_READ | PERM_WALK_CHECK_EXEC))
    return STATUS_ACCESS_DENIED;

  if (!S_ISDIR(stbuf.stx_mode)) {
    dout(10) << __func__ << " " << file_name << " failed. Not a directory." << dendl;
    return STATUS_NOT_A_DIRECTORY;
  }

  int fd = ceph_open(cmount, file_name.c_str(), O_RDONLY, 0755);
  if (fd <= 0) {
    dout(10) << __func__ << " " << file_name << ": ceph_open failed. Error: " << fd << dendl;
    return errno_to_ntstatus(fd);
  }

  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  fdc->fd = fd;

  DokanFileInfo->IsDirectory = TRUE;
  dout(20) << __func__ << " " << file_name << " - fd: " << fd << dendl;
  return 0;
}

int check_perm(string file_name, int perm_chk)
{
  if (g_cfg->enforce_perm) {
    return 0;
  }
  return permission_walk(
    cmount, file_name.c_str(),
    g_cfg->uid, g_cfg->gid,
    perm_chk);
}

int check_parent_perm(string file_name, int perm_chk)
{
  if (g_cfg->enforce_perm) {
    return 0;
  }
  return permission_walk_parent(
    cmount, file_name.c_str(),
    g_cfg->uid, g_cfg->gid,
    perm_chk);
}

static NTSTATUS do_open_file(
  string file_name,
  int flags,
  mode_t mode,
  fd_context* fdc,
  bool init_perm = false,
  umode_t new_mode = 00777)
{
  int fd = ceph_open(cmount, file_name.c_str(), flags, mode);
  if (fd < 0) {
    dout(10) << __func__ << " " << file_name
             << ": ceph_open failed. Error: " << fd << dendl;
    return errno_to_ntstatus(fd);
  }

  fdc->fd = fd;
  dout(20) << "CreateFile " << file_name << ": ceph_open OK. "
           << "fd: " << fd << dendl;

  if (init_perm) {
    ceph_chown(cmount, file_name.c_str(), g_cfg->uid, g_cfg->gid);
    fuse_init_acl(cmount, file_name.c_str(), new_mode);
  }

  return 0;
}

static NTSTATUS
WinCephCreateFile(
  LPCWSTR FileName,
  PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
  ACCESS_MASK DesiredAccess,
  ULONG FileAttributes,
  ULONG ShareMode,
  ULONG CreateDisposition,
  ULONG CreateOptions,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  // TODO: use ZwCreateFile args by default and avoid conversions.
  ACCESS_MASK AccessMode;
  DWORD FlagsAndAttributes, CreationDisposition;
  DokanMapKernelToUserCreateFileFlags(
    DesiredAccess, FileAttributes, CreateOptions, CreateDisposition,
    &AccessMode, &FlagsAndAttributes, &CreationDisposition);

  string file_name = get_path(FileName);
  dout(20) << __func__ << " " << file_name << dendl;

  if (g_cfg->debug) {
    PrintOpenParams(
      file_name.c_str(), AccessMode, FlagsAndAttributes, ShareMode,
      CreateDisposition, CreateOptions, DokanFileInfo);
  }

  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  *fdc = { 0 };
  NTSTATUS st = 0;

  struct ceph_statx stbuf;
  unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
  int ret = ceph_statx(cmount, file_name.c_str(), &stbuf, requested_attrs, 0);
  if (!ret) { /* File Exists */
    if (S_ISREG(stbuf.stx_mode)) {
      switch (CreationDisposition) {
      case CREATE_NEW:
        return STATUS_OBJECT_NAME_COLLISION;
      case TRUNCATE_EXISTING:
        // open O_TRUNC & return 0
        if (check_perm(file_name, PERM_WALK_CHECK_WRITE))
          return STATUS_ACCESS_DENIED;

        return do_open_file(file_name, O_CREAT | O_TRUNC | O_RDWR, 0755, fdc);
      case OPEN_ALWAYS:
        // open & return STATUS_OBJECT_NAME_COLLISION
        if (READ_ACCESS_REQUESTED(AccessMode) &&
            check_perm(file_name, PERM_WALK_CHECK_READ)) {
          return STATUS_ACCESS_DENIED;
        }
        if (WRITE_ACCESS_REQUESTED(AccessMode) &&
            check_perm(file_name, PERM_WALK_CHECK_WRITE)) {
          fdc->read_only = 1;
        }
        if ((st = do_open_file(file_name, fdc->read_only ? O_RDONLY : O_RDWR, 0755, fdc)))
          return st;
        return STATUS_OBJECT_NAME_COLLISION;
      case OPEN_EXISTING:
        // open & return 0
        if (READ_ACCESS_REQUESTED(AccessMode) &&
            check_perm(file_name, PERM_WALK_CHECK_READ)) {
          return STATUS_ACCESS_DENIED;
        }
        if (WRITE_ACCESS_REQUESTED(AccessMode) &&
            check_perm(file_name, PERM_WALK_CHECK_WRITE)) {
          fdc->read_only = 1;
        }
        if ((st = do_open_file(file_name, fdc->read_only ? O_RDONLY : O_RDWR, 0755, fdc)))
          return st;
        return 0;
      case CREATE_ALWAYS:
        // open O_TRUNC & return STATUS_OBJECT_NAME_COLLISION
        if (check_perm(
            file_name,
            PERM_WALK_CHECK_READ | PERM_WALK_CHECK_WRITE))
          return STATUS_ACCESS_DENIED;

        if ((st = do_open_file(file_name, O_CREAT | O_TRUNC | O_RDWR, 0755, fdc)))
          return st;
        return STATUS_OBJECT_NAME_COLLISION;
      }
    } else if (S_ISDIR(stbuf.stx_mode)) {
      DokanFileInfo->IsDirectory = TRUE;

      switch (CreationDisposition) {
      case CREATE_NEW:
        return STATUS_OBJECT_NAME_COLLISION;
      case TRUNCATE_EXISTING:
        return 0;
      case OPEN_ALWAYS:
      case OPEN_EXISTING:
        return WinCephOpenDirectory(FileName, DokanFileInfo);
      case CREATE_ALWAYS:
        return STATUS_OBJECT_NAME_COLLISION;
      }
    } else {
      DbgPrintW(L"CreateFile error. unsupported st_mode: %d [%ls]\n",
                stbuf.stx_mode, FileName);
      return STATUS_BAD_FILE_TYPE;
    }
  } else { // The file doens't exist.
    if (DokanFileInfo->IsDirectory) {
      // TODO: check create disposition.
      return WinCephCreateDirectory(FileName, DokanFileInfo);
    }
    switch (CreationDisposition) {
      case CREATE_NEW:
        // create & return 0
        if (check_parent_perm(
            file_name, PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
          return STATUS_ACCESS_DENIED;

        if ((st = do_open_file(file_name, O_CREAT | O_RDWR | O_EXCL, 0755, fdc, true)))
          return st;
        return 0;
      case CREATE_ALWAYS:
        // create & return 0
        if (check_parent_perm(
            file_name, PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
          return STATUS_ACCESS_DENIED;

        if ((st = do_open_file(file_name, O_CREAT | O_TRUNC | O_RDWR, 0755, fdc, true)))
          return st;
        return 0;
      case OPEN_ALWAYS:
        if (check_parent_perm(
            file_name,
            PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
          return STATUS_ACCESS_DENIED;

        if ((st = do_open_file(file_name, O_CREAT | O_RDWR, 0755, fdc, true)))
          return st;
        return 0;
      case OPEN_EXISTING:
        if (file_name == "/")
          return STATUS_OBJECT_NAME_NOT_FOUND;
        else
          return 0;
      case TRUNCATE_EXISTING:
        return STATUS_OBJECT_NAME_NOT_FOUND;
      default:
        DbgPrintW(L"CreateFile: unsupported create disposition: %d [%ls]",
                  CreationDisposition, FileName);
        return STATUS_INVALID_PARAMETER;
    }
  }

  // We shouldn't get here.
  fwprintf(stderr, L"CreateFile: unknown error while opening %ls.\n", FileName);
  return STATUS_INTERNAL_ERROR;
}

static void WinCephCloseFile(
  LPCWSTR FileName,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  string file_name = get_path(FileName);

  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (!fdc) {
    derr << __func__ << ": missing context: " << file_name << dendl;
    return;
  }

  dout(20) << __func__ << " " << file_name << " fd: " << fdc->fd << dendl;
  int ret = ceph_close(cmount, fdc->fd);
  if (ret) {
    dout(20) << __func__ << " " << file_name << "failed. fd: " << fdc->fd
             << "error code: " << ret << dendl;
  }

  DokanFileInfo->Context = 0;
}


static void WinCephCleanup(
  LPCWSTR FileName,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  string file_name = get_path(FileName);

  if (!DokanFileInfo->Context) {
    derr << __func__ << ": missing context: " << file_name << dendl;
    return;
  }

  if (DokanFileInfo->DeleteOnClose) {
    dout(20) << __func__ << " DeleteOnClose: " << file_name << dendl;
    if (DokanFileInfo->IsDirectory) {
      int ret = ceph_rmdir(cmount, file_name.c_str());
      if (ret)
        derr << __func__ << " " << file_name
             << ": ceph_rmdir failed. Error: " << ret << dendl;
    } else {
      int ret = ceph_unlink(cmount, file_name.c_str());
      if (ret != 0) {
        derr << __func__ << " " << file_name
             << ": ceph_unlink failed. Error: " << ret << dendl;
      }
    }
  }
}

static NTSTATUS WinCephReadFile(
  LPCWSTR FileName,
  LPVOID Buffer,
  DWORD BufferLength,
  LPDWORD ReadLength,
  LONGLONG Offset,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  if (Offset > 1024*1024*1024*1024LL || Offset < 0 ||
      BufferLength > 128*1024*1024) {
    string file_name = get_path(FileName);
    derr << "File read too large: " << file_name << ". Offset: " << Offset
         << "Buffer length: " << BufferLength << dendl;
    return STATUS_FILE_TOO_LARGE;
  }
  if (!BufferLength) {
    *ReadLength = 0;
    return 0;
  }

  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (!fdc->fd) {
    string file_name = get_path(FileName);
    dout(15) << __func__ << " " << file_name
             << ". Missing context, using temporary handle." << dendl;

    int fd_new = ceph_open(cmount, file_name.c_str(), O_RDONLY, 0);
    if (fd_new < 0) {
      dout(10) << __func__ << " " << file_name << ": ceph_open failed. Error: " << fd_new << dendl;
      return errno_to_ntstatus(fd_new);
    }

    int ret = ceph_read(cmount, fd_new, (char*) Buffer, BufferLength, Offset);
    if (ret < 0) {
      dout(10) << __func__ << " " << file_name << ": ceph_read failed. Error: " << ret
               << ". Offset: " << Offset << "Buffer length: " << BufferLength << dendl;
      ceph_close(cmount, fd_new);
      return errno_to_ntstatus(ret);
    }
    *ReadLength = ret;
    ceph_close(cmount, fd_new);
    return 0;
  } else {
    int ret = ceph_read(cmount, fdc->fd, (char*) Buffer, BufferLength, Offset);
    if (ret < 0) {
      string file_name = get_path(FileName);
      dout(10) << __func__ << " " << file_name << ": ceph_read failed. Error: " << ret
               << ". Offset: " << Offset << "Buffer length: " << BufferLength << dendl;
      return errno_to_ntstatus(ret);
    }
    *ReadLength = ret;
    return 0;
  }
}


static NTSTATUS WinCephWriteFile(
  LPCWSTR FileName,
  LPCVOID Buffer,
  DWORD NumberOfBytesToWrite,
  LPDWORD NumberOfBytesWritten,
  LONGLONG Offset,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  if (Offset > 1024*1024*1024*1024LL || Offset < 0 ||
      NumberOfBytesToWrite > 128*1024*1024) {
    string file_name = get_path(FileName);
    derr << "File write too large: " << file_name << ". Offset: " << Offset
         << "Buffer length: " << NumberOfBytesToWrite << dendl;
    return STATUS_FILE_TOO_LARGE;
  }
  if (!NumberOfBytesToWrite) {
    *NumberOfBytesWritten = 0;
    return 0;
  }
  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (fdc->read_only)
    return STATUS_ACCESS_DENIED;

  if (!fdc->fd) {
    string file_name = get_path(FileName);
    dout(15) << __func__ << " " << file_name
             << ". Missing context, using temporary handle." << dendl;

    int fd_new = ceph_open(cmount, file_name.c_str(), O_RDONLY, 0);
    if (fd_new < 0) {
      dout(10) << __func__ << " " << file_name << ": ceph_open failed. Error: " << fd_new << dendl;
      return errno_to_ntstatus(fd_new);
    }

    int ret = ceph_write(cmount, fd_new, (char*) Buffer, NumberOfBytesToWrite, Offset);
    if (ret < 0) {
      dout(10) << __func__ << " " << file_name << ": ceph_write failed. Error: " << ret
               << ". Offset: " << Offset << "Buffer length: " << NumberOfBytesToWrite << dendl;
      ceph_close(cmount, fd_new);
      return errno_to_ntstatus(ret);
    }
    *NumberOfBytesWritten = ret;
    ceph_close(cmount, fd_new);
    return 0;
  } else {
    int ret = ceph_write(cmount, fdc->fd, (char*) Buffer, NumberOfBytesToWrite, Offset);
    if (ret < 0) {
      string file_name = get_path(FileName);
      dout(10) << __func__ << " " << file_name << ": ceph_write failed. Error: " << ret
               << ". Offset: " << Offset << "Buffer length: " << NumberOfBytesToWrite << dendl;
      return errno_to_ntstatus(ret);
    }
    *NumberOfBytesWritten = ret;
    return 0;
  }
}


static NTSTATUS WinCephFlushFileBuffers(
  LPCWSTR FileName,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (!fdc->fd) {
    string file_name = get_path(FileName);
    derr << __func__ << ": missing context: " << file_name << dendl;
    return STATUS_INVALID_HANDLE;
  }

  int ret = ceph_fsync(cmount, fdc->fd, 0);
  if (ret) {
    string file_name = get_path(FileName);
    dout(10) << __func__ << " " << file_name << ": ceph_sync failed. Error: " << ret << dendl;
    return errno_to_ntstatus(ret);
  }

  return 0;
}

static NTSTATUS
WinCephGetFileInformation(
  LPCWSTR              FileName,
  LPBY_HANDLE_FILE_INFORMATION  HandleFileInformation,
  PDOKAN_FILE_INFO        DokanFileInfo)
{
  string file_name = get_path(FileName);
  dout(20) << __func__ << " " << file_name << dendl;

  memset(HandleFileInformation, 0, sizeof(BY_HANDLE_FILE_INFORMATION));

  struct ceph_statx stbuf;
  unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (!fdc->fd) {
    int ret = ceph_statx(cmount, file_name.c_str(), &stbuf, requested_attrs, 0);
    if (ret) {
      dout(10) << __func__ << " " << file_name << ": ceph_statx failed. Error: " << ret << dendl;
      return errno_to_ntstatus(ret);
    }
  } else {
    int ret = ceph_fstatx(cmount, fdc->fd, &stbuf, requested_attrs, 0);
    if (ret) {
      dout(10) << __func__ << " " << file_name << ": ceph_fstatx failed. Error: " << ret << dendl;
      return errno_to_ntstatus(ret);
    }
  }

  HandleFileInformation->nFileSizeLow = (stbuf.stx_size << 32) >> 32;
  HandleFileInformation->nFileSizeHigh = stbuf.stx_size >> 32;

  UnixTimeToFileTime(stbuf.stx_ctime.tv_sec, &HandleFileInformation->ftCreationTime);
  UnixTimeToFileTime(stbuf.stx_atime.tv_sec, &HandleFileInformation->ftLastAccessTime);
  UnixTimeToFileTime(stbuf.stx_mtime.tv_sec, &HandleFileInformation->ftLastWriteTime);

  if (S_ISDIR(stbuf.stx_mode)) {
    HandleFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
  } else if (S_ISREG(stbuf.stx_mode)) {
    HandleFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;
  }

  HandleFileInformation->nFileIndexLow = (stbuf.stx_ino << 32) >> 32;
  HandleFileInformation->nFileIndexHigh = stbuf.stx_ino >> 32;

  HandleFileInformation->nNumberOfLinks = stbuf.stx_nlink;
  return 0;
}

static NTSTATUS WinCephFindFiles(
  LPCWSTR FileName,
  PFillFindData FillFindData, // function pointer
  PDOKAN_FILE_INFO DokanFileInfo)
{
  string file_name = get_path(FileName);
  dout(20) << __func__ << " " << file_name << dendl;

  if (check_perm(file_name, PERM_WALK_CHECK_READ | PERM_WALK_CHECK_EXEC))
      return STATUS_ACCESS_DENIED;

  struct ceph_dir_result *dirp;
  int ret = ceph_opendir(cmount, file_name.c_str(), &dirp);
  if (ret != 0) {
    dout(10) << __func__ << " " << file_name
             << " ceph_mkdir failed. Error: " << ret << dendl;
    return errno_to_ntstatus(ret);
  }

  WIN32_FIND_DATAW findData;
  int count = 0;
  while (1) {
    memset(&findData, 0, sizeof(findData));
    struct dirent result;
    struct ceph_statx stbuf;

    unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
    ret = ceph_readdirplus_r(cmount, dirp, &result, &stbuf,
                             requested_attrs,
                             0,     // no special flags used when filling attrs
                             NULL); // we're not using inodes.
    if (!ret)
      break;
    if (ret < 0){
      dout(10) << __func__ << " " << file_name
               << " ceph_readdirplus_r failed. Error: " << ret << dendl;
      return errno_to_ntstatus(ret);
    }

    to_wstring(result.d_name).copy(findData.cFileName, MAX_PATH);

    findData.nFileSizeLow = (stbuf.stx_size << 32) >> 32;
    findData.nFileSizeHigh = stbuf.stx_size >> 32;

    UnixTimeToFileTime(stbuf.stx_ctime.tv_sec, &findData.ftCreationTime);
    UnixTimeToFileTime(stbuf.stx_atime.tv_sec, &findData.ftLastAccessTime);
    UnixTimeToFileTime(stbuf.stx_mtime.tv_sec, &findData.ftLastWriteTime);

    if (S_ISDIR(stbuf.stx_mode)) {
      findData.dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
    } else if (S_ISREG(stbuf.stx_mode)) {
      findData.dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;
    }

    FillFindData(&findData, DokanFileInfo);
    count++;
  }

  ceph_closedir(cmount, dirp);

  dout(20) << __func__ << " " << file_name
           << " found " << count << " entries." << dendl;
  return 0;
}

/**
 * This callback is only supposed to check if deleting a file is
 * allowed. The actual file deletion will be performed by WinCephCleanup
 */
static NTSTATUS WinCephDeleteFile(
  LPCWSTR FileName,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  string file_name = get_path(FileName);
  dout(20) << __func__ << " " << file_name << dendl;

  if (check_parent_perm(file_name, PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
    return STATUS_ACCESS_DENIED;

  return 0;
}

static NTSTATUS WinCephDeleteDirectory(
  LPCWSTR FileName,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  string file_name = get_path(FileName);
  dout(20) << __func__ << " " << file_name << dendl;

  if (check_parent_perm(file_name, PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
    return STATUS_ACCESS_DENIED;

  struct ceph_dir_result *dirp;
  int ret = ceph_opendir(cmount, file_name.c_str(), &dirp);
  if (ret != 0) {
    dout(10) << __func__ << " " << file_name
             << " ceph_opendir failed. Error: " << ret << dendl;
    return errno_to_ntstatus(ret);
  }

  WIN32_FIND_DATAW findData;
  while(1) {
    memset(&findData, 0, sizeof(findData));
    struct dirent *result = ceph_readdir(cmount, dirp);
    if (result) {
      if (strcmp(result->d_name, ".") && strcmp(result->d_name, "..")) {
        ceph_closedir(cmount, dirp);
        dout(10) << __func__ << " " << file_name
                 << ": directory is not empty. " << dendl;
        return STATUS_DIRECTORY_NOT_EMPTY;
      }
    } else break;
  }

  ceph_closedir(cmount, dirp);
  return 0;
}


static NTSTATUS WinCephMoveFile(
  LPCWSTR        FileName, // existing file name
  LPCWSTR        NewFileName,
  BOOL        ReplaceIfExisting,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR      filePath[MAX_PATH_CEPH];
  WCHAR      newFilePath[MAX_PATH_CEPH];

  GetFilePath(filePath, MAX_PATH_CEPH, FileName);
  GetFilePath(newFilePath, MAX_PATH_CEPH, NewFileName);

  DbgPrintW(L"MoveFile %ls -> %ls\n\n", filePath, newFilePath);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  char newfile_name[MAX_PATH_CEPH];
  wchar_to_char(newfile_name, NewFileName, MAX_PATH_CEPH);
  ToLinuxFilePath(newfile_name);

  DbgPrintW(L"MoveFile ceph_rename [%ls][%ls]\n", FileName, NewFileName);
  if (check_parent_perm(file_name, PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
    return STATUS_ACCESS_DENIED;

  int ret = ceph_rename(cmount, file_name, newfile_name);
  if (ret){
    DbgPrint("\terror code = %d\n\n", ret);
  }

  return errno_to_ntstatus(ret);
}

static NTSTATUS
WinCephSetEndOfFile(
  LPCWSTR FileName,
  LONGLONG ByteOffset,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (!fdc->fd) {
    string file_name = get_path(FileName);
    derr << __func__ << ": missing context: " << file_name << dendl;
    return STATUS_INVALID_HANDLE;
  }

  int ret = ceph_ftruncate(cmount, fdc->fd, ByteOffset);
  if (ret) {
    string file_name = get_path(FileName);
    dout(10) << __func__ << " " << file_name
             << " ceph_ftruncate failed. Error: " << ret
             << "Offset: " << ByteOffset << dendl;
    return errno_to_ntstatus(ret);
  }

  return 0;
}

static NTSTATUS
WinCephSetAllocationSize(
  LPCWSTR           FileName,
  LONGLONG          AllocSize,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR      filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"SetAllocationSize %ls, %I64d\n", filePath, AllocSize);

  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (!fdc->fd) {
    fwprintf(stderr, L"SetAllocationSize fdc is NULL [%ls]\n", FileName);
    return STATUS_INVALID_HANDLE;
  }

  fwprintf(stderr, L"SetAllocationSize [%ls][%d][AllocSize:%lld]\n", FileName, fdc->fd, AllocSize);

  struct ceph_statx stbuf;
  unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
  int ret = ceph_fstatx(cmount, fdc->fd, &stbuf, requested_attrs, 0);
  if (ret){
    fwprintf(stderr, L"SetAllocationSize ceph_stat error [%ls][%d][AllocSize:%lld]\n", FileName, ret, AllocSize);
    return errno_to_ntstatus(ret);
  }

  if (AllocSize < stbuf.stx_size){
    int ret = ceph_ftruncate(cmount, fdc->fd, AllocSize);
    if (ret){
      fwprintf(stderr, L"SetAllocationSize ceph_ftruncate error [%ls][%d][AllocSize:%lld]\n", FileName, ret, AllocSize);
      return errno_to_ntstatus(ret);
    }

    return 0;
  } else{
    DbgPrintW(L"SetAllocationSize ceph_ftruncate EQUAL no need [%ls][%d][AllocSize:%lld]\n", FileName, ret, AllocSize);
  }

  return 0;
}


static NTSTATUS
WinCephSetFileAttributes(
  LPCWSTR       FileName,
  DWORD         FileAttributes,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  string file_name = get_path(FileName);
  dout(20) << __func__ << " (stubbed) " << file_name << dendl;

  return 0;
}


static NTSTATUS
WinCephSetFileTime(
  LPCWSTR        FileName,
  CONST FILETIME*    CreationTime,
  CONST FILETIME*    LastAccessTime,
  CONST FILETIME*    LastWriteTime,
  PDOKAN_FILE_INFO     DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  // TODO: as per a previous inline comment, this might cause problems
  // with some apps such as MS Office (different error code than expected
  // or ctime issues probably). We might allow disabling it.
  DbgPrintW(L"SetFileTime %ls\n", filePath);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  struct ceph_statx stbuf;
  memset(&stbuf, 0, sizeof(stbuf));

  int mask = 0;
  if (CreationTime != NULL)
  {
   mask |= CEPH_SETATTR_CTIME;
   // On Windows, st_ctime is the creation time while on Linux it's the time
   // of the last metadata change. We'll try to stick with the Windows
   // semantics, although this might be overridden by Linux hosts.
   FileTimeToUnixTime(*CreationTime, &stbuf.stx_ctime.tv_sec);
  }
  if (LastAccessTime != NULL)
  {
   mask |= CEPH_SETATTR_ATIME;
   FileTimeToUnixTime(*LastAccessTime, &stbuf.stx_atime.tv_sec);
  }
  if (LastWriteTime != NULL)
  {
   mask |= CEPH_SETATTR_MTIME;
   FileTimeToUnixTime(*LastWriteTime, &stbuf.stx_mtime.tv_sec);
  }

  DbgPrintW(L"SetFileTime [%ls][st_atim:%lld][st_mtim:%lld]\n",
            FileName, stbuf.stx_atime, stbuf.stx_mtime);

  int ret = ceph_setattrx(cmount, file_name, &stbuf, mask, 0);
  if (ret){
   fwprintf(stderr, L"SetFileTime ceph_setattrx error [%ls][ret=%d]\n",
            FileName, ret);
   return errno_to_ntstatus(ret);
  }
  return 0;
}

static NTSTATUS
WinCephSetFileSecurity(
  LPCWSTR          FileName,
  PSECURITY_INFORMATION  SecurityInformation,
  PSECURITY_DESCRIPTOR  SecurityDescriptor,
  ULONG        SecurityDescriptorLength,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  string file_name = get_path(FileName);
  dout(20) << __func__ << " (stubbed) " << file_name << dendl;

  // TODO: Windows ACLs are ignored. At the moment, we're reporting this
  // operation as successful to avoid breaking applications. We might consider
  // making this behavior configurable.
  return 0;
}

static NTSTATUS
WinCephGetVolumeInformation(
  LPWSTR    VolumeNameBuffer,
  DWORD    VolumeNameSize,
  LPDWORD    VolumeSerialNumber,
  LPDWORD    MaximumComponentLength,
  LPDWORD    FileSystemFlags,
  LPWSTR    FileSystemNameBuffer,
  DWORD    FileSystemNameSize,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  wcscpy(VolumeNameBuffer, L"Ceph");
  *VolumeSerialNumber = 0x19831116;
  *MaximumComponentLength = 256;
  *FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH |
            FILE_CASE_PRESERVED_NAMES |
            FILE_SUPPORTS_REMOTE_STORAGE |
            FILE_UNICODE_ON_DISK |
            FILE_PERSISTENT_ACLS;

  wcscpy(FileSystemNameBuffer, L"Ceph");

  return 0;
}

static NTSTATUS
WinCephGetDiskFreeSpace(
  PULONGLONG FreeBytesAvailable,
  PULONGLONG TotalNumberOfBytes,
  PULONGLONG TotalNumberOfFreeBytes,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  struct statvfs vfsbuf;
  int ret = ceph_statfs(cmount, "/", &vfsbuf);
  if (ret){
    fwprintf(stderr, L"ceph_statfs error [%d]\n", ret);
    return errno_to_ntstatus(ret);;
  }

  *FreeBytesAvailable   = vfsbuf.f_bsize * vfsbuf.f_bfree;
  *TotalNumberOfBytes   = vfsbuf.f_bsize * vfsbuf.f_blocks;
  *TotalNumberOfFreeBytes = vfsbuf.f_bsize * vfsbuf.f_bfree;

  return 0;
}


static NTSTATUS
WinCephUnmount(
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  fwprintf(stderr, L"Unmounting...\n");
  ceph_unmount(cmount);
  return 0;
}

BOOL WINAPI ConsoleHandler(DWORD dwType)
{
  switch(dwType) {
  case CTRL_C_EVENT:
    printf("ctrl-c\n");
    exit(0);
  case CTRL_BREAK_EVENT:
    printf("break\n");
    break;
  default:
    printf("Some other event\n");
  }
  return TRUE;
}

static void unmount_atexit(void)
{
  int ret = ceph_unmount(cmount);
  printf("umount FINISHED [%d]\n", ret);
}

int do_map() {
  PDOKAN_OPERATIONS dokan_operations =
      (PDOKAN_OPERATIONS) malloc(sizeof(DOKAN_OPERATIONS));
  PDOKAN_OPTIONS dokan_options =
      (PDOKAN_OPTIONS) malloc(sizeof(DOKAN_OPTIONS));
  if (!dokan_operations || !dokan_options) {
    fprintf(stderr, "Not enough memory.");
    return -ENOMEM;
  }

  int r = set_dokan_options(g_cfg, dokan_options);
  if (r) {
    return r;
  }

  ZeroMemory(dokan_operations, sizeof(DOKAN_OPERATIONS));
  dokan_operations->ZwCreateFile = WinCephCreateFile;
  dokan_operations->Cleanup = WinCephCleanup;
  dokan_operations->CloseFile = WinCephCloseFile;
  dokan_operations->ReadFile = WinCephReadFile;
  dokan_operations->WriteFile = WinCephWriteFile;
  dokan_operations->FlushFileBuffers = WinCephFlushFileBuffers;
  dokan_operations->GetFileInformation = WinCephGetFileInformation;
  dokan_operations->FindFiles = WinCephFindFiles;
  dokan_operations->SetFileAttributes = WinCephSetFileAttributes;
  dokan_operations->SetFileTime = WinCephSetFileTime;
  dokan_operations->DeleteFile = WinCephDeleteFile;
  dokan_operations->DeleteDirectory = WinCephDeleteDirectory;
  dokan_operations->MoveFile = WinCephMoveFile;
  dokan_operations->SetEndOfFile = WinCephSetEndOfFile;
  dokan_operations->SetAllocationSize = WinCephSetAllocationSize;
  dokan_operations->SetFileSecurity = WinCephSetFileSecurity;
  dokan_operations->GetDiskFreeSpace = WinCephGetDiskFreeSpace;
  dokan_operations->GetVolumeInformation = WinCephGetVolumeInformation;
  dokan_operations->Unmounted = WinCephUnmount;

  int ret = 0;
  ceph_create_with_context(&cmount, g_ceph_context);

  ret = ceph_mount(cmount, g_cfg->root_path.c_str());
  if (ret) {
    fprintf(stderr, "ceph_mount error [%d]!\n", ret);
    return errno_to_ntstatus(ret);
  }
  fprintf(stderr, "ceph_mount OK\n");

  atexit(unmount_atexit);

  fprintf(stderr, "ceph_getcwd [%s]\n", ceph_getcwd(cmount));

  DWORD status = DokanMain(dokan_options, dokan_operations);
  switch (status) {
  case DOKAN_SUCCESS:
    fprintf(stderr, "Dokan returned successfully.\n");
    break;
  case DOKAN_ERROR:
    fprintf(stderr, "Dokan error.\n");
    break;
  case DOKAN_DRIVE_LETTER_ERROR:
    fprintf(stderr, "Bad Drive letter.\n");
    break;
  case DOKAN_DRIVER_INSTALL_ERROR:
    fprintf(stderr, "Can't install Dokan driver.\n");
    break;
  case DOKAN_START_ERROR:
    fprintf(stderr, "Dokan start error.\n");
    break;
  case DOKAN_MOUNT_ERROR:
    fprintf(stderr, "Dokan mount error.\n");
    break;
  case DOKAN_MOUNT_POINT_ERROR:
    fprintf(stderr, "Mount point error.\n");
    break;
  default:
    fprintf(stderr, "Unknown Dokan error: %d.\n", status);
    break;
  }

  free(dokan_options);
  free(dokan_operations);
  return 0;
}

boost::intrusive_ptr<CephContext> do_global_init(
  int argc, const char *argv[], Command cmd)
{
  std::vector<const char*> args;
  argv_to_vec(argc, argv, args);

  code_environment_t code_env;
  int flags;

  switch (cmd) {
    case Command::Map:
      code_env = CODE_ENVIRONMENT_DAEMON;
      flags = CINIT_FLAG_UNPRIVILEGED_DAEMON_DEFAULTS;
      break;
    default:
      code_env = CODE_ENVIRONMENT_UTILITY;
      flags = CINIT_FLAG_NO_MON_CONFIG;
      break;
  }

  global_pre_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, code_env, flags);
  // Avoid cluttering the console when spawning a mapping that will run
  // in the background.
  if (g_conf()->daemonize) {
    flags |= CINIT_FLAG_NO_DAEMON_ACTIONS;
  }
  auto cct = global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT,
                         code_env, flags, FALSE);

  // There's no fork on Windows, we should be safe calling this anytime.
  common_init_finish(g_ceph_context);
  global_init_chdir(g_ceph_context);

  return cct;
}

int main(int argc, char* argv[])
{
  fprintf(stderr,
          "WARNING: This is a preview version of ceph-dokan. "
          "The CLI might change in subsequent versions.\n");

  g_cfg = new Config;

  if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE)) {
    fwprintf(stderr, L"Unable to install console handler!\n");
    return -EINVAL;
  }

  Command cmd = Command::None;
  std::vector<const char*> args;
  argv_to_vec(argc, argv, args);
  std::ostringstream err_msg;
  int r = parse_args(args, &err_msg, &cmd, g_cfg);
  if (r) {
    std::cerr << err_msg.str() << std::endl;
    return r;
  }

  switch (cmd) {
    case Command::Version:
      std::cout << pretty_version_to_str() << std::endl;
      return 0;
    case Command::Help:
      print_usage();
      return 0;
    default:
      break;
  }

  auto cct = do_global_init(argc, argv, cmd);

  switch (cmd) {
    case Command::Map:
      return do_map();
    default:
      print_usage();
      break;
  }

  return 0;
}

