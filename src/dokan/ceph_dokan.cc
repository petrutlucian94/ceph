/*
  A CephFS Client on Win32 (based on Dokan)
*/

#define UNICODE
#define _UNICODE

#include "include/compat.h"
#include "include/cephfs/libcephfs.h"

#include "dbg.h"
#include <ntstatus.h>

#include "posix_acl.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <fileinfo.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sddl.h>
#include <accctrl.h>
#include <aclapi.h>

#include "common/ceph_argparse.h"
#include "common/config.h"
#include "common/debug.h"
#include "common/dout.h"
#include "common/errno.h"
#include "common/version.h"

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
long timeout_ms = CEPH_DOKAN_IO_DEFAULT_TIMEOUT;

struct fd_context{
  int   fd;
  short read_only;
};

static WCHAR MountPoint[MAX_PATH_CEPH] = L"";
static char ceph_conf_file[MAX_PATH_CEPH] = "";
static WCHAR Wceph_conf_file[MAX_PATH_CEPH] = L"";
static WCHAR Wargv0[MAX_PATH_CEPH];

static void
GetFilePath(
  PWCHAR  filePath,
  ULONG  numberOfElements,
  LPCWSTR FileName)
{
  RtlZeroMemory(filePath, numberOfElements * sizeof(WCHAR));
  wcsncat(filePath, FileName, wcslen(FileName));
}

static NTSTATUS
WinCephCreateDirectory(
  LPCWSTR          FileName,
  PDOKAN_FILE_INFO    DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"CreateDirectory : %ls\n", filePath);
  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  if(strcmp(file_name, "/")==0)
  {
    return 0;
  }

  if(g_UseACL)
  {
    /* permission check*/
    int st = permission_walk_parent(cmount, file_name, g_UID, g_GID,
                    PERM_WALK_CHECK_WRITE|PERM_WALK_CHECK_EXEC);
    if(st)
      return STATUS_ACCESS_DENIED;
  }

  struct ceph_statx stbuf;
  unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
  int ret = ceph_statx(cmount, file_name, &stbuf, requested_attrs, 0);
  if(ret==0){
    if(S_ISDIR(stbuf.stx_mode)){
      fwprintf(stderr, L"CreateDirectory ceph_mkdir EXISTS [%ls][ret=%d]\n", FileName, ret);
      return STATUS_OBJECT_NAME_COLLISION;
    }
  }

  ret = ceph_mkdir(cmount, file_name, 0755);
  if(ret<0)
  {
    fwprintf(stderr, L"CreateDirectory ceph_mkdir ERROR [%ls][ret=%d]\n", FileName, ret);
    return errno_to_ntstatus(ret);
  }

  ceph_chown(cmount, file_name, g_UID, g_GID);
  fuse_init_acl(cmount, file_name, 0040777); //S_IRWXU|S_IRWXG|S_IRWXO|S_IFDIR
  return 0;
}

static int
WinCephOpenDirectory(
  LPCWSTR          FileName,
  PDOKAN_FILE_INFO    DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];
  wcscpy(filePath, FileName);

  DbgPrintW(L"OpenDirectory : %ls\n", filePath);
  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, filePath, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  struct ceph_statx stbuf;
  unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
  int ret = ceph_statx(cmount, file_name, &stbuf, requested_attrs, 0);
  if(ret){
    fwprintf(stderr, L"OpenDirectory ceph_stat ERROR [%ls][ret=%d]\n", FileName, ret);
    return errno_to_ntstatus(ret);
  }

  if(g_UseACL)
  {
    /* permission check*/
    int st = permission_walk(cmount, file_name, g_UID, g_GID,
                    PERM_WALK_CHECK_READ|PERM_WALK_CHECK_EXEC);
    if(st)
      return STATUS_ACCESS_DENIED;
  }

  if(!S_ISDIR(stbuf.stx_mode)) {
    DbgPrintW(L"OpenDirectory error: not a directory: %ls\n", FileName);
    return STATUS_NOT_A_DIRECTORY;
  }

  int fd = ceph_open(cmount, file_name, O_RDONLY, 0755);
  if(fd <= 0){
    fwprintf(stderr, L"OpenDirectory ceph_opendir error : %ls [fd:%d]\n", FileName, fd);
    return errno_to_ntstatus(fd);
  }

  struct fd_context fdc;
  memset(&fdc, 0, sizeof(struct fd_context));

  fdc.fd = fd;
  memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));

  //DokanFileInfo->IsDirectory = TRUE;
  DbgPrintW(L"OpenDirectory OK : %s [fd:%d]\n", FileName, fd);
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

  WCHAR filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  if (ShareMode == 0 && AccessMode & FILE_WRITE_DATA)
    ShareMode = FILE_SHARE_WRITE;
  else if (ShareMode == 0)
    ShareMode = FILE_SHARE_READ;

  PrintOpenParams(
    filePath, AccessMode, FlagsAndAttributes, ShareMode,
    CreateDisposition, CreateOptions, DokanFileInfo);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  struct fd_context fdc;
  memset(&fdc, 0, sizeof(struct fd_context));

  int fd = 0;
  struct ceph_statx stbuf;
  unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
  int ret = ceph_statx(cmount, file_name, &stbuf, requested_attrs, 0);
  if(ret==0) /*File Exists*/
  {
    if(S_ISREG(stbuf.stx_mode))
    {
      switch (CreationDisposition) {
        case CREATE_NEW:
          return STATUS_OBJECT_NAME_COLLISION;
        case TRUNCATE_EXISTING:
          //open O_TRUNC & return 0
          if(g_UseACL)
          {
            /* permission check*/
            int st = permission_walk(cmount, file_name, g_UID, g_GID,
                            PERM_WALK_CHECK_WRITE);
            if(st)
              return STATUS_ACCESS_DENIED;
          }
          fd = ceph_open(cmount, file_name, O_CREAT|O_TRUNC|O_RDWR, 0755);
          if(fd<0){
            fwprintf(stderr, L"CreateFile REG TRUNCATE_EXISTING ceph_open error [%ls][ret=%d]\n", FileName, fd);
            return errno_to_ntstatus(fd);
          }

          fdc.fd = fd;
          memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
          DbgPrintW(L"CreateFile REG TRUNCATE_EXISTING ceph_open OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
            (int)DokanFileInfo->Context);

          return 0;
        case OPEN_ALWAYS:
          //open & return STATUS_OBJECT_NAME_COLLISION
          if(READ_ACCESS_REQUESTED(AccessMode))
          {
            if(g_UseACL)
            {
              /* permission check*/
              int st = permission_walk(cmount, file_name, g_UID, g_GID,
                              PERM_WALK_CHECK_READ);
              if(st)
                return STATUS_ACCESS_DENIED;
            }
          }

          if(WRITE_ACCESS_REQUESTED(AccessMode))
          {
            if(g_UseACL)
            {
              /* permission check*/
              int st = permission_walk(cmount, file_name, g_UID, g_GID,
                              PERM_WALK_CHECK_WRITE);
              if(st) fdc.read_only = 1;
            }
          }

          if(fdc.read_only == 1)
            fd = ceph_open(cmount, file_name, O_RDONLY, 0755);
          else
            fd = ceph_open(cmount, file_name, O_RDWR, 0755);
          if(fd<0){
            fwprintf(stderr, L"CreateFile REG OPEN_ALWAYS ceph_open error [%ls][ret=%d]\n", FileName, fd);
            return errno_to_ntstatus(fd);
          }

          fdc.fd = fd;
          memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
          DbgPrintW(L"CreateFile ceph_open REG OPEN_ALWAYS OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
            (int)DokanFileInfo->Context);

          return STATUS_OBJECT_NAME_COLLISION;
        case OPEN_EXISTING:
          //open & return 0
          if(READ_ACCESS_REQUESTED(AccessMode))
          {
            DbgPrintW(L"CreateFile REG OPEN_EXISTING ceph_open ACL READ [%ls]\n", FileName);
            if(g_UseACL)
            {
              /* permission check*/
              int st = permission_walk(cmount, file_name, g_UID, g_GID,
                              PERM_WALK_CHECK_READ);
              if(st)
                return STATUS_ACCESS_DENIED;
            }
          }

          if(WRITE_ACCESS_REQUESTED(AccessMode))
          {
            DbgPrintW(L"CreateFile REG OPEN_EXISTING ceph_open ACL WRITE [%ls]\n", FileName);
            if(g_UseACL)
            {
              /* permission check*/
              int st = permission_walk(cmount, file_name, g_UID, g_GID,
                              PERM_WALK_CHECK_WRITE);
              if(st) fdc.read_only = 1;
            }
          }

          if(fdc.read_only == 1)
            fd = ceph_open(cmount, file_name, O_RDONLY, 0755);
          else
            fd = ceph_open(cmount, file_name, O_RDWR, 0755);
          if(fd<0){
            fwprintf(stderr, L"CreateFile ceph_open REG OPEN_EXISTING error [%ls][ret=%d]\n", FileName, fd);
            return errno_to_ntstatus(fd);
          }
          fdc.fd = fd;
          memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
          DbgPrintW(L"CreateFile ceph_open REG OPEN_EXISTING OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
            (int)DokanFileInfo->Context);

          return 0;
        case CREATE_ALWAYS:
          //open O_TRUNC & return STATUS_OBJECT_NAME_COLLISION
          if(g_UseACL)
          {
            /* permission check*/
            int st = permission_walk(cmount, file_name, g_UID, g_GID,
                            PERM_WALK_CHECK_READ|PERM_WALK_CHECK_WRITE);
            if(st)
              return STATUS_ACCESS_DENIED;
          }
          fd = ceph_open(cmount, file_name, O_CREAT|O_TRUNC|O_RDWR, 0755);
          if(fd<0){
            fwprintf(stderr, L"CreateFile ceph_open error REG CREATE_ALWAYS [%ls][ret=%d]\n", FileName, fd);
            return errno_to_ntstatus(fd);
          }

          fdc.fd = fd;
          memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
          DbgPrintW(L"CreateFile ceph_open REG CREATE_ALWAYS OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
            (int)DokanFileInfo->Context);

          return STATUS_OBJECT_NAME_COLLISION;
      }
    }
    else if(S_ISDIR(stbuf.stx_mode))
    {
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
    }else {
      DbgPrintW(L"CreateFile error. unsupported st_mode: %d [%ls]\n",
                stbuf.stx_mode, FileName);
      return STATUS_BAD_FILE_TYPE;
    }
  }
  else /*File Not Exists*/
  {
    if(DokanFileInfo->IsDirectory)
    {
      // TODO: check create disposition.
      return WinCephCreateDirectory(FileName, DokanFileInfo);
    }
    switch (CreationDisposition) {
      case CREATE_NEW:
        //create & return 0
        if(g_UseACL)
        {
          /* permission check*/
          int st = permission_walk_parent(cmount, file_name, g_UID, g_GID,
                          PERM_WALK_CHECK_WRITE|PERM_WALK_CHECK_EXEC);
          if(st)
            return STATUS_ACCESS_DENIED;
        }
        fd = ceph_open(cmount, file_name, O_CREAT|O_RDWR|O_EXCL, 0755);
        if(fd<0){
          fwprintf(stderr, L"CreateFile NOF CREATE_NEW ceph_open error [%ls][ret=%d]\n", FileName, fd);
          return errno_to_ntstatus(fd);
        }

        fdc.fd = fd;
        memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
        DbgPrintW(L"CreateFile ceph_open NOF CREATE_NEW OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
          (int)DokanFileInfo->Context);

        ceph_chown(cmount, file_name, g_UID, g_GID);
        fuse_init_acl(cmount, file_name, 00777); //S_IRWXU|S_IRWXG|S_IRWXO
        return 0;
      case CREATE_ALWAYS:
        //create & return 0
        if(g_UseACL)
        {
          /* permission check*/
          int st = permission_walk_parent(cmount, file_name, g_UID, g_GID,
                          PERM_WALK_CHECK_WRITE|PERM_WALK_CHECK_EXEC);
          if(st)
            return STATUS_ACCESS_DENIED;
        }
        fd = ceph_open(cmount, file_name, O_CREAT|O_TRUNC|O_RDWR, 0755);
        if(fd<0){
          fwprintf(stderr, L"CreateFile NOF CREATE_ALWAYS ceph_open error [%ls][ret=%d]\n", FileName, fd);
          return errno_to_ntstatus(fd);
        }

        fdc.fd = fd;
        memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
        DbgPrintW(L"CreateFile ceph_open NOF CREATE_ALWAYS_ALWAYS OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
          (int)DokanFileInfo->Context);

        ceph_chown(cmount, file_name, g_UID, g_GID);
        fuse_init_acl(cmount, file_name, 00777); //S_IRWXU|S_IRWXG|S_IRWXO
        return 0;
      case OPEN_ALWAYS:
        if(g_UseACL)
        {
          /* permission check*/
          int st = permission_walk_parent(cmount, file_name, g_UID, g_GID,
                          PERM_WALK_CHECK_WRITE|PERM_WALK_CHECK_EXEC);
          if(st)
            return STATUS_ACCESS_DENIED;
        }
        fd = ceph_open(cmount, file_name, O_CREAT|O_RDWR, 0755);
        if(fd<=0){
          fwprintf(stderr, L"CreateFile REG NOF OPEN_ALWAYS ceph_open error [%ls][ret=%d]\n", FileName, fd);
          return errno_to_ntstatus(fd);
        }

        fdc.fd = fd;
        memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
        DbgPrintW(L"CreateFile ceph_open REG NOF OPEN_ALWAYS OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
          (int)DokanFileInfo->Context);

        ceph_chown(cmount, file_name, g_UID, g_GID);
        fuse_init_acl(cmount, file_name, 00777); //S_IRWXU|S_IRWXG|S_IRWXO
        return 0;
      case OPEN_EXISTING:
        if (file_name[0] == '/')
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

static void
WinCephCloseFile(
  LPCWSTR          FileName,
  PDOKAN_FILE_INFO    DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  if(!DokanFileInfo->Context) {
    DbgPrintW(L"Close: invalid handle %ls\n\n", filePath);
    return;
  }

  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));

  DbgPrintW(L"CloseFile: %ls\n", filePath);
  DbgPrintW(L"ceph_close [%ls][fd=%d]\n", FileName, fdc.fd);
  int ret = ceph_close(cmount, fdc.fd);
  if(ret){
    DbgPrint("\terror code = %d\n\n", ret);
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

  if(!DokanFileInfo->Context) {
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
  if(Offset > 1024*1024*1024*1024LL || Offset < 0 ||
     BufferLength > 128*1024*1024){
    fwprintf(stderr, L"File write too large [fn:%ls][Offset=%lld][BufferLength=%ld]\n",FileName, Offset, BufferLength);
    return STATUS_FILE_TOO_LARGE;
  }
  if(BufferLength == 0)
  {
    *ReadLength = 0;
    return 0;
  }

  GetFilePath(filePath, MAX_PATH_CEPH, FileName);
  DbgPrintW(L"ReadFile : %ls\n", filePath);

  if(BufferLength == 0)
  {
    fwprintf(stderr, L"ceph_read BufferLength==0 [fn:%ls][Offset=%ld]\n",FileName, Offset);
    *ReadLength = 0;
    return 0;
  }

  DbgPrintW(L"ceph_read [Offset=%lld][BufferLength=%ld]\n", Offset, BufferLength);
  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));
  if(fdc.fd == 0){
    char file_name[MAX_PATH_CEPH];
    wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
    ToLinuxFilePath(file_name);

    fwprintf(stderr, L"ceph_read reopen fd [fn:%ls][Offset=%ld]\n", FileName, Offset);

    int fd_new = ceph_open(cmount, file_name, O_RDONLY, 0);
    if(fd_new < 0)
    {
      fwprintf(stderr, L"ceph_read reopen fd [fn:%ls][fd_new=%d][Offset=%ld]\n", FileName, fd_new, Offset);
      return errno_to_ntstatus(fd_new);
    }

    int ret = ceph_read(cmount, fd_new, Buffer, BufferLength, Offset);
    if(ret<0)
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
    int ret = ceph_read(cmount, fdc.fd, Buffer, BufferLength, Offset);
    if(ret<0)
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
  if(Offset > 1024*1024*1024*1024LL || Offset < 0 ||
      NumberOfBytesToWrite > 128*1024*1024){
    fwprintf(stderr, L"FILE WIRTE TOO LARGE [fn:%ls][Offset=%lld][NumberOfBytesToWrite=%ld]\n", FileName, Offset, NumberOfBytesToWrite);
    return STATUS_FILE_TOO_LARGE;
  }
  if(NumberOfBytesToWrite == 0)
  {
    *NumberOfBytesWritten = 0;
    return 0;
  }
  DbgPrintW(L"WriteFile : %ls, offset %I64d, length %d\n", filePath, Offset, NumberOfBytesToWrite);
  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));

  if(fdc.read_only == 1)
    return STATUS_ACCESS_DENIED;

  if(fdc.fd==0){
    char file_name[MAX_PATH_CEPH];
    wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
    ToLinuxFilePath(file_name);

    fwprintf(stderr, L"ceph_write reopen fd [fn:%ls][Offset=%ld]\n",FileName, Offset);

    int fd_new = ceph_open(cmount, file_name, O_RDONLY, 0);
    if(fd_new < 0)
    {
      fwprintf(stderr, L"ceph_write reopen fd [fn:%ls][fd_new=%d][Offset=%ld]\n", FileName, fd_new, Offset);
      return errno_to_ntstatus(fd_new);
    }

    int ret = ceph_write(cmount, fd_new, Buffer, NumberOfBytesToWrite, Offset);
    if(ret<0)
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
  else{
    int ret = ceph_write(cmount, fdc.fd, Buffer, NumberOfBytesToWrite, Offset);
    if(ret<0)
    {
      fwprintf(stderr, L"ceph_write IO error [fn:%ls][ret=%d][fd=%d][Offset=%lld][Length=%ld]\n",
               FileName, ret, fdc.fd, Offset, NumberOfBytesToWrite);
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

  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));
  if(fdc.fd==0){
    fwprintf(stderr, L"ceph_sync FD error [%ls] fdc is NULL\n", FileName);
    return STATUS_INVALID_HANDLE;
  }

  int ret = ceph_fsync(cmount, fdc.fd, 0);
  if(ret){
    fwprintf(stderr, L"ceph_sync error [%ls][%df][ret=%d]\n",
             FileName, fdc.fd, ret);
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
  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));
  if (fdc.fd==0) {
    int ret = ceph_statx(cmount, file_name, &stbuf, requested_attrs, 0);
    if(ret){
      DbgPrintW(L"GetFileInformation ceph_stat error [%ls]\n", FileName);
      return errno_to_ntstatus(ret);
    }
  }else{
    int ret = ceph_fstatx(cmount, fdc.fd, &stbuf, requested_attrs, 0);
    if(ret){
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
  if(S_ISDIR(stbuf.stx_mode)){
    DbgPrintW(L"[%ls] is a Directory.............\n", FileName);
    HandleFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
  }
  else if(S_ISREG(stbuf.stx_mode)){
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

  if(g_UseACL)
  {
    /* permission check*/
    int st = permission_walk(cmount, file_name, g_UID, g_GID,
                    PERM_WALK_CHECK_READ|PERM_WALK_CHECK_EXEC);
    if(st)
      return STATUS_ACCESS_DENIED;
  }

  struct ceph_dir_result *dirp;
  int ret = ceph_opendir(cmount, file_name, &dirp);
  if(ret != 0){
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
    if(ret==0)
      break;
    if(ret<0){
      fprintf(stderr, "FindFiles ceph_readdirplus_r error [%ls][ret=%d]\n", FileName, ret);
      return errno_to_ntstatus(ret);
    }

    // TODO: check if "." or ".." need any special handling.
    if(strcmp(result.d_name, ".")==0 || strcmp(result.d_name, "..")==0){
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
    if(S_ISDIR(stbuf.stx_mode)){
      //printf("[%s] is a Directory.............\n", result.d_name);
      findData.dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
    }
    else if(S_ISREG(stbuf.stx_mode)){
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

  if(g_UseACL)
  {
    /* permission check*/
    int st = permission_walk_parent(cmount, file_name, g_UID, g_GID,
                    PERM_WALK_CHECK_WRITE|PERM_WALK_CHECK_EXEC);
    if(st)
      return STATUS_ACCESS_DENIED;
  }

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

  if(g_UseACL)
  {
    /* permission check*/
    int st = permission_walk_parent(cmount, file_name, g_UID, g_GID,
                    PERM_WALK_CHECK_WRITE|PERM_WALK_CHECK_EXEC);
    if(st)
      return STATUS_ACCESS_DENIED;
  }

  struct ceph_dir_result *dirp;
  int ret = ceph_opendir(cmount, file_name, &dirp);
  if(ret != 0){
    fwprintf(stderr, L"ceph_opendir error : %ls [%d]\n", FileName, ret);
    return errno_to_ntstatus(ret);
  }

  DbgPrintW(L"DeleteDirectory ceph_opendir OK: %ls\n", FileName);

  while(1)
  {
    memset(&findData, 0, sizeof(findData));
    struct dirent *result = ceph_readdir(cmount, dirp);
    if(result!=NULL)
    {
      if(strcmp(result->d_name, ".")!=0
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
  if(g_UseACL)
  {
    /* permission check*/
    int st = permission_walk_parent(cmount, file_name, g_UID, g_GID,
                    PERM_WALK_CHECK_WRITE|PERM_WALK_CHECK_EXEC);
    if(st)
      return STATUS_ACCESS_DENIED;
  }

  int ret = ceph_rename(cmount, file_name, newfile_name);
  if(ret){
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

  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));
  if (fdc.fd==0) {
    DbgPrintW(L"\tinvalid handle\n\n");
    fwprintf(stderr, L"SetEndOfFile fdc is NULL [%ls]\n", FileName);
    return STATUS_INVALID_HANDLE;
  }

  DbgPrintW(L"SetEndOfFile [%ls][%d][ByteOffset:%lld]\n", FileName, fdc.fd, ByteOffset);

  int ret = ceph_ftruncate(cmount, fdc.fd, ByteOffset);
  if(ret){
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

  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));
  if (fdc.fd==0) {
    fwprintf(stderr, L"SetAllocationSize fdc is NULL [%ls]\n", FileName);
    return STATUS_INVALID_HANDLE;
  }

  fwprintf(stderr, L"SetAllocationSize [%ls][%d][AllocSize:%lld]\n", FileName, fdc.fd, AllocSize);

  struct ceph_statx stbuf;
  unsigned int requested_attrs = CEPH_STATX_BASIC_STATS;
  int ret = ceph_fstatx(cmount, fdc.fd, &stbuf, requested_attrs, 0);
  if(ret){
    fwprintf(stderr, L"SetAllocationSize ceph_stat error [%ls][%d][AllocSize:%lld]\n", FileName, ret, AllocSize);
    return errno_to_ntstatus(ret);
  }

  if(AllocSize < stbuf.stx_size){
    int ret = ceph_ftruncate(cmount, fdc.fd, AllocSize);
    if(ret){
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
  if(CreationTime != NULL)
  {
   mask |= CEPH_SETATTR_CTIME;
   // On Windows, st_ctime is the creation time while on Linux it's the time
   // of the last metadata change. We'll try to stick with the Windows
   // semantics, although this might be overridden by Linux hosts.
   FileTimeToUnixTime(*CreationTime, &stbuf.stx_ctime.tv_sec);
  }
  if(LastAccessTime != NULL)
  {
   mask |= CEPH_SETATTR_ATIME;
   FileTimeToUnixTime(*LastAccessTime, &stbuf.stx_atime.tv_sec);
  }
  if(LastWriteTime != NULL)
  {
   mask |= CEPH_SETATTR_MTIME;
   FileTimeToUnixTime(*LastWriteTime, &stbuf.stx_mtime.tv_sec);
  }

  DbgPrintW(L"SetFileTime [%ls][st_atim:%lld][st_mtim:%lld]\n",
            FileName, stbuf.stx_atime, stbuf.stx_mtime);

  int ret = ceph_setattrx(cmount, file_name, &stbuf, mask, 0);
  if(ret){
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
  if(ret){
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

void ceph_show_version() {
    int major, minor, ppatch;
    const char* char_version = ceph_version(&major, &minor, &ppatch);
    fprintf(stderr, "%s\n", char_version);
}

static int parse_args(std::vector<const char*>& args,
                      std::ostream *err_msg,
                      Command *command, Config *cfg) {
  std::string conf_file_list;
  std::string cluster;
  CephInitParameters iparams = ceph_argparse_early_args(
          args, CEPH_ENTITY_TYPE_CLIENT, &cluster, &conf_file_list);

  ConfigProxy config{false};
  config->name = iparams.name;
  config->cluster = cluster;
  if (!conf_file_list.empty()) {
    config.parse_config_files(conf_file_list.c_str(), nullptr, 0);
  } else {
    config.parse_config_files(nullptr, nullptr, 0);
  }
  config.parse_env(CEPH_ENTITY_TYPE_CLIENT);
  config.parse_argv(args);

  std::vector<const char*>::iterator i;
  std::ostringstream err;

  for (i = args.begin(); i != args.end(); ) {
    if (ceph_argparse_flag(args, i, "-h", "--help", (char*)NULL)) {
      return HELP_INFO;
    } else if (ceph_argparse_flag(args, i, "-v", "--version", (char*)NULL)) {
      return VERSION_INFO;
    } else if (ceph_argparse_witharg(args, i, &cfg->devpath, "l", "--mountpoint", (char *)NULL)) {
    } else if (ceph_argparse_witharg(args, i, &cfg->mount_subdir, "x", "--subdir", (char *)NULL)) {
    } else if (ceph_argparse_flag(args, i, "w", "--read-only", (char *)NULL)) {
      cfg->readonly = true;
    } else if (ceph_argparse_flag(args, i, "m", "--removable", (char *)NULL)) {
      cfg->removable = true;
    } else if (ceph_argparse_flag(args, i, "o", "--win-mount-mgr", (char *)NULL)) {
      cfg->use_win_mount_mgr = true;
    } else if (ceph_argparse_flag(args, i, "p", "--current-session-only", (char *)NULL)) {
      cfg->current_session_only = true;
    } else if (ceph_argparse_flag(args, i, "n", "--no-acl", (char *)NULL)) {
      cfg->use_acl = false;
    } else if (ceph_argparse_witharg(args, i, (int*)&cfg->uid,
                                     err, "u", "--uid", (char *)NULL)) {
      if (!err.str().empty()) {
        *err_msg << "rbd-nbd: " << err.str();
        return -EINVAL;
      }
      if (cfg->uid < 0) {
        *err_msg << "rbd-nbd: Invalid argument for uid";
        return -EINVAL;
      }
    } else if (ceph_argparse_witharg(args, i, (int*)&cfg->gid,
                                     err, "g", "--gid", (char *)NULL)) {
      if (!err.str().empty()) {
        *err_msg << "rbd-nbd: " << err.str();
        return -EINVAL;
      }
      if (cfg->gid < 0) {
        *err_msg << "rbd-nbd: Invalid argument for gid";
        return -EINVAL;
      }
    } else {
      ++i;
    }
  }

  Command cmd = None;
  if (args.begin() != args.end()) {
    if (strcmp(*args.begin(), "map") == 0) {
      cmd = Connect;
    } else if (strcmp(*args.begin(), "unmap") == 0) {
      cmd = Disconnect;
    } else if (strcmp(*args.begin(), "list") == 0) {
      cmd = List;
    } else if (strcmp(*args.begin(), "show") == 0) {
      cmd = Show;
    } else if (strcmp(*args.begin(), "service") == 0) {
      cmd = Service;
    } else if (strcmp(*args.begin(), "stats") == 0) {
      cmd = Stats;
    } else if (strcmp(*args.begin(), "help") == 0) {
      return HELP_INFO;
    } else {
      *err_msg << "rbd-wnbd: unknown command: " <<  *args.begin();
      return -EINVAL;
    }
    args.erase(args.begin());
  }

  if (cmd == None) {
    *err_msg << "rbd-wnbd: must specify command";
    return -EINVAL;
  }

  switch (cmd) {
    case Connect:
    case Disconnect:
    case Show:
    case Stats:
      if (args.begin() == args.end()) {
        *err_msg << "rbd-wnbd: must specify wnbd device or image-or-snap-spec";
        return -EINVAL;
      }
      if (parse_imgpath(*args.begin(), cfg, err_msg) < 0) {
        return -EINVAL;
      }
      args.erase(args.begin());
      break;
    default:
      //shut up gcc;
      break;
  }

  if (args.begin() != args.end()) {
    *err_msg << "rbd-wnbd: unknown args: " << *args.begin();
    return -EINVAL;
  }

  *command = cmd;
  return 0;

}

static void print_usage() {
  fprintf(stderr, "ceph-dokan.exe\n"
    "  -c CephConfFile  (ex. /r c:\\ceph.conf)\n"
    "  -l DriveLetter (ex. /l m)\n"
    "  -t ThreadCount (ex. /t 5)\n"
    "  -d (enable debug output)\n"
    "  -s (use stderr for output)\n"
    "  -m (use removable drive)\n"
    "  -o (use Windows mount manager)\n"
    "  -c (mount for the current session only)\n"
    "  -w (write-protect drive - read only mount)\n"
    "  -u Uid (use the specified uid when mounting, defaults to 0)\n"
    "  -g Gid (use the specified gid when mounting, defaults to 0)\n"
    "  -n (skip enforcing permissions on client side)\n"
    "  -x sub_mount_path (mount a Ceph filesystem subdirectory)\n"
    "  -h (show this help message)\n"
    "  -i (operation timeout in seconds, defaults to 120)\n"
    );
}


int __cdecl
main(int argc, char* argv[])
{
  char sub_mount_path[4096];
  strcpy(sub_mount_path, "/");

  int status;
  ULONG command;
  PDOKAN_OPERATIONS dokanOperations =
      (PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
  PDOKAN_OPTIONS dokanOptions =
      (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));

  fprintf(stderr,
          "WARNING: This is a preview version of ceph-dokan. "
          "The CLI might change in subsequent versions.\n");

  if(argc==2)
  {
    // TODO: argument parsing can be improved. We might consider
    // switching to Ceph helpers.
    // We'll soon start adding a bunch of options that should probably
    // reside in a config file, ideally ceph.conf
    if(strcmp(argv[1], "--version")==0 || strcmp(argv[1], "-v")==0)
    {
      ceph_show_version();
      return 0;
    }
    if(strcmp(argv[1], "--help")==0 || strcmp(argv[1], "-h")==0)
    {
      ceph_show_version();
      print_usage();
      return 0;
    }
  }

  if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE)) {
    fwprintf(stderr, L"Unable to install console handler!\n");
    return EXIT_FAILURE;
  }

  g_DebugMode = FALSE;
  g_UseStdErr = FALSE;

  ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
  dokanOptions->Version = DOKAN_VERSION;
  dokanOptions->ThreadCount = 10;

  WCHAR wargv[32][512];
  for (command = 0; command < argc; command++) {
    MultiByteToWideChar(CP_UTF8, 0, (LPCTSTR)argv[command], -1, wargv[command], 512);
    DbgPrintW(L"argv command:[%d] %ls\n", command, wargv[command]);
  }

  wcscpy(Wargv0, wargv[0]);

  for (command = 1; command < argc; command++) {
    switch (towlower(wargv[command][1])) {
    case L'c':
      command++;
      strcpy(ceph_conf_file, argv[command]);
      wcscpy(Wceph_conf_file, wargv[command]);
      DbgPrintW(L"ceph_conf_file: %ls\n", ceph_conf_file);
      break;
    case L'l':
      command++;
      wcscpy(MountPoint, wargv[command]);
      dokanOptions->MountPoint = MountPoint;
      break;
    case L't':
      command++;
      dokanOptions->ThreadCount = (USHORT)_wtoi(wargv[command]);
      break;
    case L'd':
      g_DebugMode = TRUE;
      fwprintf(stderr, L"g_DebugMode = TRUE\n");
      break;
    case L's':
      g_UseStdErr = TRUE;
      fwprintf(stderr, L"g_UseStdErr = TRUE\n");
      break;
    case L'u':
      command++;
      g_UID = (USHORT)_wtoi(wargv[command]);
      break;
    case L'g':
      command++;
      g_GID = (USHORT)_wtoi(wargv[command]);
      break;
    case L'a':
      g_UseACL = TRUE;
      break;
    case L'x':
      command++;
      strcpy(sub_mount_path, argv[command]);
      break;
    case L'm':
      dokanOptions->Options |= DOKAN_OPTION_REMOVABLE;
      break;
    case L'o':
      dokanOptions->Options |= DOKAN_OPTION_MOUNT_MANAGER;
      break;
    case L'p':
      dokanOptions->Options |= DOKAN_OPTION_CURRENT_SESSION;
      break;
    case L'w':
      dokanOptions->Options |= DOKAN_OPTION_WRITE_PROTECT;
      break;
    case L'i':
      command++;
      timeout_ms = _wtol(wargv[command]) * 1000;
      break;
    default:
      fwprintf(stderr, L"unknown command: %ls\n", wargv[command]);
      return ERROR_INVALID_PARAMETER;
    }
  }

  if (!wcslen(MountPoint)) {
    fwprintf(stderr, L"No mountpoint was specified.\n");
    return ERROR_INVALID_PARAMETER;
  }

  if (g_DebugMode) {
    dokanOptions->Options |= DOKAN_OPTION_DEBUG;
  }
  if (g_UseStdErr) {
    dokanOptions->Options |= DOKAN_OPTION_STDERR;
  }

  if ((dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) &&
      (dokanOptions->Options & DOKAN_OPTION_CURRENT_SESSION)) {
    fwprintf(stderr,
             L"The mount manager always mounts the drive for all user sessions.\n");
    return EXIT_FAILURE;
  }

  dokanOptions->Timeout = timeout_ms;

  ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
  dokanOperations->ZwCreateFile = WinCephCreateFile;
  dokanOperations->Cleanup = WinCephCleanup;
  dokanOperations->CloseFile = WinCephCloseFile;
  dokanOperations->ReadFile = WinCephReadFile;
  dokanOperations->WriteFile = WinCephWriteFile;
  dokanOperations->FlushFileBuffers = WinCephFlushFileBuffers;
  dokanOperations->GetFileInformation = WinCephGetFileInformation;
  dokanOperations->FindFiles = WinCephFindFiles;
  dokanOperations->SetFileAttributes = WinCephSetFileAttributes;
  dokanOperations->SetFileTime = WinCephSetFileTime;
  dokanOperations->DeleteFile = WinCephDeleteFile;
  dokanOperations->DeleteDirectory = WinCephDeleteDirectory;
  dokanOperations->MoveFile = WinCephMoveFile;
  dokanOperations->SetEndOfFile = WinCephSetEndOfFile;
  dokanOperations->SetAllocationSize = WinCephSetAllocationSize;
  dokanOperations->SetFileSecurity = WinCephSetFileSecurity;
  dokanOperations->GetDiskFreeSpace = WinCephGetDiskFreeSpace;
  dokanOperations->GetVolumeInformation = WinCephGetVolumeInformation;
  dokanOperations->Unmounted = WinCephUnmount;

  //ceph_mount
  int ret = 0;
  ceph_create(&cmount, NULL);
  ret = ceph_conf_read_file(
    cmount,
    strlen(ceph_conf_file) ? ceph_conf_file : NULL);

  if(ret)
  {
    fprintf(stderr, "ceph_conf_read_file error [%d]!\n", ret);
    return errno_to_ntstatus(ret);
  }
  fprintf(stderr, "ceph_conf_read_file OK\n");

  ret = ceph_mount(cmount, sub_mount_path);
  if(ret)
  {
    fprintf(stderr, "ceph_mount error [%d]!\n", ret);
    return errno_to_ntstatus(ret);
  }

  fprintf(stderr, "ceph_mount OK\n");

  atexit(unmount_atexit);

  fprintf(stderr, "ceph_getcwd [%s]\n", ceph_getcwd(cmount));

  status = DokanMain(dokanOptions, dokanOperations);
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

  free(dokanOptions);
  free(dokanOperations);
  return 0;
}

