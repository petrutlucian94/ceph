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

// Used as part of DOKAN_FILE_INFO.Context, must fit within 64B.
typedef struct {
  int   fd;
  short read_only;
} fd_context, *pfd_context;
assert(sizeof(fd_context) <= sizeof(DOKAN_FILE_INFO.Context))

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
    dout(10) << __func__   << " " << file_name << " failed. Error: " << ret << dendl;
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

static int check_perm(string file_name, int perm_chk)
{
  if (g_cfg->enforce_perm) {
    return 0;
  }
  return permission_walk(
    cmount, file_name.c_str(),
    g_cfg->uid, g_cfg->gid,
    perm_chk);
}

static int check_parent_perm(string file_name, int perm_chk)
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
  fd = ceph_open(cmount, file_name.c_str(), flags, mode);
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
  NTSTAUS st = 0;

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
        if (st = do_open_file(file_name, fdc->read_only ? O_RDONLY : O_RDWR, 0755, fdc))
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
        if (st = do_open_file(file_name, fdc->read_only ? O_RDONLY : O_RDWR, 0755, fdc))
          return st;
        return 0;
      case CREATE_ALWAYS:
        // open O_TRUNC & return STATUS_OBJECT_NAME_COLLISION
        if (check_perm(
            file_name,
            PERM_WALK_CHECK_READ | PERM_WALK_CHECK_WRITE))
          return STATUS_ACCESS_DENIED;

        if (st = do_open_file(file_name, O_CREAT | O_TRUNC | O_RDWR, 0755, fdc))
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
  } else { /*File Not Exists*/
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

        if (st = do_open_file(file_name, O_CREAT | O_RDWR | O_EXCL, 0755, fdc, true))
          return st;
        return 0;
      case CREATE_ALWAYS:
        // create & return 0
        if (check_parent_perm(
            file_name, PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
          return STATUS_ACCESS_DENIED;

        if (st = do_open_file(file_name, O_CREAT | O_TRUNC | O_RDWR, 0755, fdc, true))
          return st;
        return 0;
      case OPEN_ALWAYS:
        if (check_parent_perm(
            file_name,
            PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
          return STATUS_ACCESS_DENIED;

        if (st = do_open_file(file_name, O_CREAT | O_RDWR, 0755, fdc, true))
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
    derr << "Close: missing context: " << file_name << dendl;
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


static void
WinCephCleanup(
  LPCWSTR          FileName,
  PDOKAN_FILE_INFO    DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  if (!DokanFileInfo->Context) {
    DbgPrintW(L"Cleanup: invalid handle %ls\n\n", filePath);
    return;
  }

  if (DokanFileInfo->DeleteOnClose) {
    DbgPrintW(L"Cleanup DeleteOnClose: %ls\n", filePath);
    if (DokanFileInfo->IsDirectory) {
      DbgPrintW(L"cleanup ceph_rmdir [%ls]\n", FileName);
      int ret = ceph_rmdir(cmount, file_name);
      if (ret != 0) {
        DbgPrintW(L"error code = %d\n\n", ret);
      } else {
        DbgPrintW(L"success\n\n");
      }
    } else {
      DbgPrintW(L"cleanup ceph_unlink [%ls]\n", FileName);
      int ret = ceph_unlink(cmount, file_name);
      if (ret != 0) {
        DbgPrintW(L" error code = %d\n\n", ret);
      } else {
        DbgPrintW(L"success\n\n");
      }
    }
  }
}


static NTSTATUS
WinCephReadFile(
  LPCWSTR        FileName,
  LPVOID         Buffer,
  DWORD          BufferLength,
  LPDWORD        ReadLength,
  LONGLONG       Offset,
  PDOKAN_FILE_INFO   DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  if (Offset > 1024*1024*1024*1024LL || Offset < 0 ||
     BufferLength > 128*1024*1024){
    fwprintf(stderr, L"File write too large [fn:%ls][Offset=%lld][BufferLength=%ld]\n", FileName, Offset, BufferLength);
    return STATUS_FILE_TOO_LARGE;
  }
  if (BufferLength == 0)
  {
    *ReadLength = 0;
    return 0;
  }

  GetFilePath(filePath, MAX_PATH_CEPH, FileName);
  DbgPrintW(L"ReadFile : %ls\n", filePath);

  if (BufferLength == 0)
  {
    fwprintf(stderr, L"ceph_read BufferLength==0 [fn:%ls][Offset=%ld]\n",FileName, Offset);
    *ReadLength = 0;
    return 0;
  }

  DbgPrintW(L"ceph_read [Offset=%lld][BufferLength=%ld]\n", Offset, BufferLength);
  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (!fdc->fd){
    char file_name[MAX_PATH_CEPH];
    wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
    ToLinuxFilePath(file_name);

    fwprintf(stderr, L"ceph_read reopen fd [fn:%ls][Offset=%ld]\n", FileName, Offset);

    int fd_new = ceph_open(cmount, file_name, O_RDONLY, 0);
    if (fd_new < 0)
    {
      fwprintf(stderr, L"ceph_read reopen fd [fn:%ls][fd_new=%d][Offset=%ld]\n", FileName, fd_new, Offset);
      return errno_to_ntstatus(fd_new);
    }

    int ret = ceph_read(cmount, fd_new, Buffer, BufferLength, Offset);
    if (ret<0)
    {
      fwprintf(stderr, L"ceph_read IO error [Offset=%ld][ret=%d]\n", Offset, ret);
      ceph_close(cmount, fd_new);
      return errno_to_ntstatus(ret);
    }
    *ReadLength = ret;
    ceph_close(cmount, fd_new);
    return 0;
  }
  else{
    int ret = ceph_read(cmount, fdc->fd, Buffer, BufferLength, Offset);
    if (ret<0)
    {
      fwprintf(stderr, L"ceph_read IO error [Offset=%ld][ret=%d]\n", Offset, ret);
      return errno_to_ntstatus(ret);
    }
    *ReadLength = ret;

    return 0;
  }
}


static NTSTATUS
WinCephWriteFile(
  LPCWSTR    FileName,
  LPCVOID    Buffer,
  DWORD    NumberOfBytesToWrite,
  LPDWORD    NumberOfBytesWritten,
  LONGLONG      Offset,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  if (Offset > 1024*1024*1024*1024LL || Offset < 0 ||
      NumberOfBytesToWrite > 128*1024*1024){
    fwprintf(stderr, L"FILE WIRTE TOO LARGE [fn:%ls][Offset=%lld][NumberOfBytesToWrite=%ld]\n", FileName, Offset, NumberOfBytesToWrite);
    return STATUS_FILE_TOO_LARGE;
  }
  if (NumberOfBytesToWrite == 0)
  {
    *NumberOfBytesWritten = 0;
    return 0;
  }
  DbgPrintW(L"WriteFile : %ls, offset %I64d, length %d\n", filePath, Offset, NumberOfBytesToWrite);
  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);

  if (fdc->read_only)
    return STATUS_ACCESS_DENIED;

  if (!fdc->fd) {
    char file_name[MAX_PATH_CEPH];
    wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
    ToLinuxFilePath(file_name);

    fwprintf(stderr, L"ceph_write reopen fd [fn:%ls][Offset=%ld]\n",FileName, Offset);

    int fd_new = ceph_open(cmount, file_name, O_RDONLY, 0);
    if (fd_new < 0)
    {
      fwprintf(stderr, L"ceph_write reopen fd [fn:%ls][fd_new=%d][Offset=%ld]\n", FileName, fd_new, Offset);
      return errno_to_ntstatus(fd_new);
    }

    int ret = ceph_write(cmount, fd_new, Buffer, NumberOfBytesToWrite, Offset);
    if (ret<0)
    {
      fwprintf(stderr, L"ceph_write IO error [fn:%ls][ret=%d][fd=%d][Offset=%lld][Length=%ld]\n",
               FileName, ret, fd_new, Offset, NumberOfBytesToWrite);
      ceph_close(cmount, fd_new);
      return errno_to_ntstatus(ret);
    }
    *NumberOfBytesWritten = ret;

    ceph_close(cmount, fd_new);
    return 0;
  }
  else {
    int ret = ceph_write(cmount, fdc->fd, Buffer, NumberOfBytesToWrite, Offset);
    if (ret<0)
    {
      fwprintf(stderr, L"ceph_write IO error [fn:%ls][ret=%d][fd=%d][Offset=%lld][Length=%ld]\n",
               FileName, ret, fdc->fd, Offset, NumberOfBytesToWrite);
      return errno_to_ntstatus(ret);
    }
    *NumberOfBytesWritten = ret;

    return 0;
  }
}


static NTSTATUS
WinCephFlushFileBuffers(
  LPCWSTR    FileName,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];

  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"FlushFileBuffers : %ls\n", filePath);

  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (!fdc->fd) {
    fwprintf(stderr, L"ceph_sync FD error [%ls] fdc is NULL\n", FileName);
    return STATUS_INVALID_HANDLE;
  }

  int ret = ceph_fsync(cmount, fdc->fd, 0);
  if (ret){
    fwprintf(stderr, L"ceph_sync error [%ls][%df][ret=%d]\n",
             FileName, fdc->fd, ret);
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
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"GetFileInfo : %ls\n", filePath);

  memset(HandleFileInformation, 0, sizeof(BY_HANDLE_FILE_INFORMATION));

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  struct ceph_statx stbuf;
  unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (!fdc->fd) {
    int ret = ceph_statx(cmount, file_name, &stbuf, requested_attrs, 0);
    if (ret){
      DbgPrintW(L"GetFileInformation ceph_stat error [%ls]\n", FileName);
      return errno_to_ntstatus(ret);
    }
  }else{
    int ret = ceph_fstatx(cmount, fdc->fd, &stbuf, requested_attrs, 0);
    if (ret){
      fwprintf(stderr, L"GetFileInformation ceph_fstat error [%ls][ret=%d]\n",
               FileName, ret);
      return errno_to_ntstatus(ret);
    }
  }

  DbgPrintW(L"GetFileInformation1 [%ls][size:%lld][time:%lld]\n",
    FileName, stbuf.stx_size, stbuf.stx_mtime);
  //fill stbuf.stx_size
  HandleFileInformation->nFileSizeLow = (stbuf.stx_size << 32)>>32;
  HandleFileInformation->nFileSizeHigh = stbuf.stx_size >> 32;

  //fill stbuf.stx_mtim
  UnixTimeToFileTime(stbuf.stx_ctime.tv_sec, &HandleFileInformation->ftCreationTime);
  UnixTimeToFileTime(stbuf.stx_atime.tv_sec, &HandleFileInformation->ftLastAccessTime);
  UnixTimeToFileTime(stbuf.stx_mtime.tv_sec, &HandleFileInformation->ftLastWriteTime);

  DbgPrintW(L"GetFileInformation6 [%ls][size:%lld][time a:%lld m:%lld c:%lld]\n",
    FileName, stbuf.stx_size, stbuf.stx_atime, stbuf.stx_mtime, stbuf.stx_ctime.tv_sec);

  //fill stbuf.stx_mode
  if (S_ISDIR(stbuf.stx_mode)){
    DbgPrintW(L"[%ls] is a Directory.............\n", FileName);
    HandleFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
  }
  else if (S_ISREG(stbuf.stx_mode)){
    DbgPrintW(L"[%ls] is a Regular File.............\n", FileName);
    HandleFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;
  }

  //fill stbuf.stx_ino
  HandleFileInformation->nFileIndexLow = (stbuf.stx_ino << 32)>>32;
  HandleFileInformation->nFileIndexHigh = stbuf.stx_ino >> 32;

  //fill stbuf.stx_nlink
  HandleFileInformation->nNumberOfLinks = stbuf.stx_nlink;

  return 0;
}

static NTSTATUS
WinCephFindFiles(
  LPCWSTR        FileName,
  PFillFindData    FillFindData, // function pointer
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR        filePath[MAX_PATH_CEPH];
  WIN32_FIND_DATAW  findData;
  PWCHAR        yenStar = L"\\*";
  int count = 0;

  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  wcscat(filePath, yenStar);
  DbgPrintW(L"FindFiles :%ls\n", filePath);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);

  ToLinuxFilePath(file_name);

  DbgPrintW(L"FindFiles ceph_opendir : [%ls]\n", FileName);

  if (check_perm(file_name, PERM_WALK_CHECK_READ | PERM_WALK_CHECK_EXEC))
      return STATUS_ACCESS_DENIED;

  struct ceph_dir_result *dirp;
  int ret = ceph_opendir(cmount, file_name, &dirp);
  if (ret != 0){
    fwprintf(stderr, L"ceph_opendir error : %ls [ret=%d]\n", FileName, ret);
    return errno_to_ntstatus(ret);
  }

  DbgPrintW(L"FindFiles ceph_opendir OK: %ls\n", FileName);

  while(1)
  {
    memset(&findData, 0, sizeof(findData));
    struct dirent result;
    struct ceph_statx stbuf;

    unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
    ret = ceph_readdirplus_r(cmount, dirp, &result, &stbuf,
                             requested_attrs,
                             0,     // no special flags used when filling attrs
                             NULL); // we're not using inodes.
    if (ret==0)
      break;
    if (ret<0){
      fprintf(stderr, "FindFiles ceph_readdirplus_r error [%ls][ret=%d]\n", FileName, ret);
      return errno_to_ntstatus(ret);
    }

    // TODO: check if "." or ".." need any special handling.
    if (strcmp(result.d_name, ".")==0 || strcmp(result.d_name, "..")==0){
    //   continue;
    }

    //d_name
    WCHAR d_name[MAX_PATH_CEPH];
    char_to_wchar(d_name, result.d_name, MAX_PATH_CEPH);

    wcscpy(findData.cFileName, d_name);

    //stx_size
    findData.nFileSizeLow = (stbuf.stx_size << 32)>>32;
    findData.nFileSizeHigh = stbuf.stx_size >> 32;

    //stx_mtim
    UnixTimeToFileTime(stbuf.stx_ctime.tv_sec, &findData.ftCreationTime);
    UnixTimeToFileTime(stbuf.stx_atime.tv_sec, &findData.ftLastAccessTime);
    UnixTimeToFileTime(stbuf.stx_mtime.tv_sec, &findData.ftLastWriteTime);

    //stx_mode
    if (S_ISDIR(stbuf.stx_mode)){
      //printf("[%s] is a Directory.............\n", result.d_name);
      findData.dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
    }
    else if (S_ISREG(stbuf.stx_mode)){
      //printf("[%s] is a Regular File.............\n", result.d_name);
      findData.dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;
    }

    FillFindData(&findData, DokanFileInfo);
    count++;
    DbgPrintW(L"findData.cFileName is [%ls]\n", findData.cFileName);
    DbgPrintW(L"ceph_readdir [%d][%s]\n", count, result.d_name);
  }

  ret = ceph_closedir(cmount, dirp);

  DbgPrintW(L"\tFindFiles return %d entries in %ls\n\n", count, filePath);
  return 0;
}

/**
 * This callback is only supposed to check if deleting a file is
 * allowed. The actual file deletion will be performed by WinCephCleanup
 */
static NTSTATUS
WinCephDeleteFile(
  LPCWSTR        FileName,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"DeleteFile %ls\n", filePath);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  if (check_parent_perm(file_name, PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
    return STATUS_ACCESS_DENIED;

  return 0;
}

static NTSTATUS
WinCephDeleteDirectory(
  LPCWSTR        FileName,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];
  WIN32_FIND_DATAW findData;

  ZeroMemory(filePath, sizeof(filePath));
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"DeleteDirectory %ls\n", filePath);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  DbgPrintW(L"DeleteDirectory ceph_rmdir [%ls]\n", FileName);

  if (check_parent_perm(file_name, PERM_WALK_CHECK_WRITE | PERM_WALK_CHECK_EXEC))
    return STATUS_ACCESS_DENIED;

  struct ceph_dir_result *dirp;
  int ret = ceph_opendir(cmount, file_name, &dirp);
  if (ret != 0){
    fwprintf(stderr, L"ceph_opendir error : %ls [%d]\n", FileName, ret);
    return errno_to_ntstatus(ret);
  }

  DbgPrintW(L"DeleteDirectory ceph_opendir OK: %ls\n", FileName);

  while(1)
  {
    memset(&findData, 0, sizeof(findData));
    struct dirent *result = ceph_readdir(cmount, dirp);
    if (result!=NULL)
    {
      if (strcmp(result->d_name, ".")!=0
        && strcmp(result->d_name, "..")!=0)
      {
        ceph_closedir(cmount, dirp);
        DbgPrintW(L"  Directory is not empty: %ls\n", findData.cFileName);
        return STATUS_DIRECTORY_NOT_EMPTY;
      }
    }else break;
  }

  ceph_closedir(cmount, dirp);
  return 0;
}


static NTSTATUS
WinCephMoveFile(
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
  LPCWSTR        FileName,
  LONGLONG      ByteOffset,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR      filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);
  DbgPrintW(L"SetEndOfFile %ls, %I64d\n", filePath, ByteOffset);

  pfd_context fdc = (pfd_context) &(DokanFileInfo->Context);
  if (!fdc->fd) {
    DbgPrintW(L"\tinvalid handle\n\n");
    fwprintf(stderr, L"SetEndOfFile fdc is NULL [%ls]\n", FileName);
    return STATUS_INVALID_HANDLE;
  }

  DbgPrintW(L"SetEndOfFile [%ls][%d][ByteOffset:%lld]\n", FileName, fdc->fd, ByteOffset);

  int ret = ceph_ftruncate(cmount, fdc->fd, ByteOffset);
  if (ret){
    fwprintf(stderr, L"SetEndOfFile ceph_ftruncate error [%ls][%d][ByteOffset:%lld]\n", FileName, ret, ByteOffset);
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
  }
  else{
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
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"SetFileAttributes [%ls][%d]\n", FileName, FileAttributes);

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
  WCHAR filePath[MAX_PATH_CEPH];

  GetFilePath(filePath, MAX_PATH_CEPH, FileName);
  DbgPrintW(L"SetFileSecurity (stubbed) %ls\n", filePath);

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

