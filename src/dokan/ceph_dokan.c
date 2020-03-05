/*
  A CephFS Client on Win32 (based on Dokan)
*/

#define UNICODE
#define _UNICODE

#include "include/compat.h"
#include "include/cephfs/libcephfs.h"

#include <stdio.h>
#include <stdlib.h>

#include <dokan.h>
#include <fileinfo.h>

#include "dbg.h"
#include "posix_acl.h"
#include "utils.h"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sddl.h>

#include <accctrl.h>
#include <aclapi.h>

#define MAX_PATH_CEPH 8192
#define CEPH_DOKAN_IO_TIMEOUT 1000 * 60 * 2

#define READ_ACCESS_REQUESTED(access_mode) \
    access_mode & GENERIC_READ || \
    access_mode & FILE_SHARE_READ || \
    access_mode & STANDARD_RIGHTS_READ || \
    access_mode & FILE_SHARE_READ
#define WRITE_ACCESS_REQUESTED(access_mode) \
    access_mode & GENERIC_WRITE || \
    access_mode & FILE_SHARE_WRITE || \
    access_mode & STANDARD_RIGHTS_WRITE || \
    access_mode & FILE_SHARE_WRITE

BOOL g_UseStdErr;
BOOL g_DebugMode;

int g_UID = 0;
int g_GID = 0;
BOOL g_UseACL  = FALSE;
struct ceph_mount_info *cmount;

struct fd_context{
  int   fd;
  short delete_on_close;
  short read_only;
};

static WCHAR MountPoint[MAX_PATH_CEPH] = L"M:";
static char ceph_conf_file[MAX_PATH_CEPH];
static WCHAR Wceph_conf_file[MAX_PATH_CEPH];
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

static int
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

  if(FlagsAndAttributes & FILE_ATTRIBUTE_TEMPORARY ||
     FlagsAndAttributes & FILE_FLAG_DELETE_ON_CLOSE)
  {
    fdc.delete_on_close = TRUE;
  }

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  int fd = 0;
  if(strcmp(file_name, "/")==0)
  {
    return 0;
  }
  else
  {
    struct stat st_buf;
    int ret = ceph_stat(cmount, file_name, &st_buf);
    if(ret==0) /*File Exists*/
    {
      if(S_ISREG(st_buf.st_mode))
      {
        switch (CreationDisposition) {
          case CREATE_NEW:
            return -ERROR_FILE_EXISTS;
          case TRUNCATE_EXISTING:
            //open O_TRUNC & return 0
            if(g_UseACL)
            {
              /* permission check*/
              int st = permission_walk(cmount, file_name, g_UID, g_GID,
                              PERM_WALK_CHECK_WRITE);
              if(st)
                return -ERROR_ACCESS_DENIED;
            }
            fd = ceph_open(cmount, file_name, O_CREAT|O_TRUNC|O_RDWR, 0755);
            if(fd<0){
              fwprintf(stderr, L"CreateFile REG TRUNCATE_EXISTING ceph_open error [%ls][ret=%d]\n", FileName, fd);
              return fd;
            }

            fdc.fd = fd;
            memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
            DbgPrintW(L"CreateFile REG TRUNCATE_EXISTING ceph_open OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
              (int)DokanFileInfo->Context);

            return 0;
          case OPEN_ALWAYS:
            //open & return ERROR_ALREADY_EXISTS
            if(READ_ACCESS_REQUESTED(AccessMode))
            {
              if(g_UseACL)
              {
                /* permission check*/
                int st = permission_walk(cmount, file_name, g_UID, g_GID,
                                PERM_WALK_CHECK_READ);
                if(st)
                  return -ERROR_ACCESS_DENIED;
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
              return fd;
            }

            fdc.fd = fd;
            memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
            DbgPrintW(L"CreateFile ceph_open REG OPEN_ALWAYS OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
              (int)DokanFileInfo->Context);

            return ERROR_ALREADY_EXISTS;
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
                  return -ERROR_ACCESS_DENIED;
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
              return fd;
            }
            fdc.fd = fd;
            memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
            DbgPrintW(L"CreateFile ceph_open REG OPEN_EXISTING OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
              (int)DokanFileInfo->Context);

            return 0;
          case CREATE_ALWAYS:
            //open O_TRUNC & return ERROR_ALREADY_EXISTS
            if(g_UseACL)
            {
              /* permission check*/
              int st = permission_walk(cmount, file_name, g_UID, g_GID,
                              PERM_WALK_CHECK_READ|PERM_WALK_CHECK_WRITE);
              if(st)
                return -ERROR_ACCESS_DENIED;
            }
            fd = ceph_open(cmount, file_name, O_CREAT|O_TRUNC|O_RDWR, 0755);
            if(fd<0){
              fwprintf(stderr, L"CreateFile ceph_open error REG CREATE_ALWAYS [%ls][ret=%d]\n", FileName, fd);
              return fd;
            }

            fdc.fd = fd;
            memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));
            DbgPrintW(L"CreateFile ceph_open REG CREATE_ALWAYS OK [%ls][fd=%d][Context=%d]\n", FileName, fd,
              (int)DokanFileInfo->Context);

            return ERROR_ALREADY_EXISTS;
        }
      }
      else if(S_ISDIR(st_buf.st_mode))
      {
        DokanFileInfo->IsDirectory = TRUE;

        switch (CreationDisposition) {
          case CREATE_NEW:
            return -ERROR_FILE_EXISTS;
          case TRUNCATE_EXISTING:
            return 0;
          case OPEN_ALWAYS:
          case OPEN_EXISTING:
            return WinCephOpenDirectory(FileName, DokanFileInfo);
          case CREATE_ALWAYS:
            return ERROR_ALREADY_EXISTS;
        }
      }else
        return -1;
    }
    else /*File Not Exists*/
    {
      if(DokanFileInfo->IsDirectory)
      {
        // TODO:
        // * check create disposition.
        // * return the right error when the directory exists
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
              return -ERROR_ACCESS_DENIED;
          }
          fd = ceph_open(cmount, file_name, O_CREAT|O_RDWR|O_EXCL, 0755);
          if(fd<0){
            fwprintf(stderr, L"CreateFile NOF CREATE_NEW ceph_open error [%ls][ret=%d]\n", FileName, fd);
            return -1;
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
              return -ERROR_ACCESS_DENIED;
          }
          fd = ceph_open(cmount, file_name, O_CREAT|O_TRUNC|O_RDWR, 0755);
          if(fd<0){
            fwprintf(stderr, L"CreateFile NOF CREATE_ALWAYS ceph_open error [%ls][ret=%d]\n", FileName, fd);
            return -1;
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
              return -ERROR_ACCESS_DENIED;
          }
          fd = ceph_open(cmount, file_name, O_CREAT|O_RDWR, 0755);
          if(fd<=0){
            fwprintf(stderr, L"CreateFile REG NOF OPEN_ALWAYS ceph_open error [%ls][ret=%d]\n", FileName, fd);
            return -1;
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
            return -ERROR_FILE_NOT_FOUND;
          else
            return 0;
        case TRUNCATE_EXISTING:
          return -ERROR_FILE_NOT_FOUND;
      }
    }
  }

  return -1;
}

int
WinCephCreateDirectory(
  LPCWSTR          FileName,
  PDOKAN_FILE_INFO    DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"CreateDirectory : %ls\n", filePath);
  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

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
      return -ERROR_ACCESS_DENIED;
  }

  struct stat st_buf;
  int ret = ceph_stat(cmount, file_name, &st_buf);
  if(ret==0){
    if(S_ISDIR(st_buf.st_mode)){
      fwprintf(stderr, L"CreateDirectory ceph_mkdir EXISTS [%ls][ret=%d]\n", FileName, ret);
      return -ERROR_ALREADY_EXISTS;
    }
  }

  ret = ceph_mkdir(cmount, file_name, 0755);
  if(ret == -2)
  {
    fwprintf(stderr, L"CreateDirectory ceph_mkdir ENOENT [%ls][ret=%d]\n", FileName, ret);
    return -ERROR_PATH_NOT_FOUND;
  }else if(ret){
    fwprintf(stderr, L"CreateDirectory ceph_mkdir ERROR [%ls][ret=%d]\n", FileName, ret);
    return -5;
  }

  if(g_UseACL){
    ceph_chown(cmount, file_name, g_UID, g_GID);
    fuse_init_acl(cmount, file_name, 0040777); //S_IRWXU|S_IRWXG|S_IRWXO|S_IFDIR
  }
  return 0;
}

int
WinCephOpenDirectory(
  LPCWSTR          FileName,
  PDOKAN_FILE_INFO    DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];
  wcscpy(filePath, FileName);

  DbgPrintW(L"OpenDirectory : %ls\n", filePath);
  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, filePath, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  struct stat st_buf;
  int ret = ceph_stat(cmount, file_name, &st_buf);
  if(ret){
    fwprintf(stderr, L"OpenDirectory ceph_stat ERROR [%ls][ret=%d]\n", FileName, ret);
    return -1;
  }

  if(g_UseACL)
  {
    /* permission check*/
    int st = permission_walk(cmount, file_name, g_UID, g_GID,
                    PERM_WALK_CHECK_READ|PERM_WALK_CHECK_EXEC);
    if(st)
      return -ERROR_ACCESS_DENIED;
  }

  if(S_ISDIR(st_buf.st_mode)){
    int fd = ceph_open(cmount, file_name, O_RDONLY, 0755);
    if(fd <= 0){
      fwprintf(stderr, L"OpenDirectory ceph_opendir error : %ls [fd:%d]\n", FileName, fd);
      return -1;
    }

    struct fd_context fdc;
    memset(&fdc, 0, sizeof(struct fd_context));

    fdc.fd = fd;
    memcpy(&(DokanFileInfo->Context), &fdc, sizeof(fdc));

    //DokanFileInfo->IsDirectory = TRUE;
    DbgPrintW(L"OpenDirectory OK : %s [fd:%d]\n", FileName, fd);
    return 0;
  }
  else
    return -1;
}

static int
WinCephCloseFile(
  LPCWSTR          FileName,
  PDOKAN_FILE_INFO    DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  if (DokanFileInfo->Context) {
    DbgPrintW(L"CloseFile: %ls\n", filePath);
    DbgPrintW(L"\terror: the file context wasn't cleaned up.\n\n");

    char file_name[MAX_PATH_CEPH];
    wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
    ToLinuxFilePath(file_name);

    struct fd_context fdc;
    memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));

    DbgPrintW(L"ceph_close [%ls][fd=%d]\n", FileName, fdc.fd);

    int ret = ceph_close(cmount, fdc.fd);
    if(ret){
      DbgPrint("\terror code = %d\n\n", ret);
      // TODO: check if this error needs to be propagated or at least logged.
      // Since this was commented out, high chance is that it's happening
      // quite often.
      //return ret;
    }

    DokanFileInfo->Context = 0;

    if(fdc.delete_on_close)
    {
      if(DokanFileInfo->IsDirectory == FALSE)
      {
        int ret = ceph_unlink(cmount, file_name);
        if (ret != 0) {
          DbgPrintW(L"DeleteOnClose ceph_unlink error code = %d\n\n", ret);
        } else {
          DbgPrintW(L"DeleteOnClose ceph_unlink success\n\n");
        }
        fwprintf(stderr, L"fdc.delete_on_close [%ls]\n", FileName);
      }
    }
  } else {
    DbgPrintW(L"Close: %ls\n\tinvalid handle\n\n", filePath);
    return 0;
  }
  return 0;
}


static int
WinCephCleanup(
  LPCWSTR          FileName,
  PDOKAN_FILE_INFO    DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  if (DokanFileInfo->Context) {
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

  } else {
    DbgPrintW(L"Cleanup: %ls\n\tinvalid handle\n\n", filePath);
    return -1;
  }

  return 0;
}


static int
WinCephReadFile(
  LPCWSTR        FileName,
  LPVOID         Buffer,
  DWORD        BufferLength,
  LPDWORD        ReadLength,
  LONGLONG       Offset,
  PDOKAN_FILE_INFO   DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  if(Offset > 1024*1024*1024*1024LL || Offset < 0 || BufferLength < 0
      || BufferLength > 128*1024*1024){
    fwprintf(stderr, L"File write too large [fn:%ls][Offset=%lld][BufferLength=%ld]\n",FileName, Offset, BufferLength);
    return -1; //ERROR_FILE_TOO_LARGE
  }
  if(BufferLength == 0)
  {
    *ReadLength = 0;
    return 0;
  }

  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"ReadFile : %ls\n", filePath);

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

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
      return -1;
    }

    int ret = ceph_read(cmount, fd_new, Buffer, BufferLength, Offset);
    if(ret<0)
    {
      fwprintf(stderr, L"ceph_read IO error [Offset=%ld][ret=%d]\n", Offset, ret);
      ceph_close(cmount, fd_new);
      return ret;
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
      return ret;
    }
    *ReadLength = ret;

    return 0;
  }
}


static int
WinCephWriteFile(
  LPCWSTR    FileName,
  LPCVOID    Buffer,
  DWORD    NumberOfBytesToWrite,
  LPDWORD    NumberOfBytesWritten,
  LONGLONG      Offset,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  if(Offset > 1024*1024*1024*1024LL || Offset < 0 || NumberOfBytesToWrite < 0
      || NumberOfBytesToWrite > 128*1024*1024){
    fwprintf(stderr, L"FIlE WIRTE TOO LARGE [fn:%ls][Offset=%lld][NumberOfBytesToWrite=%ld]\n", FileName, Offset, NumberOfBytesToWrite);
    return -1; //ERROR_FILE_TOO_LARGE
  }
  if(NumberOfBytesToWrite == 0)
  {
    *NumberOfBytesWritten = 0;
    return 0;
  }
  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  DbgPrintW(L"WriteFile : %ls, offset %I64d, length %d\n", filePath, Offset, NumberOfBytesToWrite);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  DbgPrintW(L"ceph_write [Offset=%lld][NumberOfBytesToWrite=%ld]\n", Offset, NumberOfBytesToWrite);
  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));

  if(fdc.read_only == 1)
    return -ERROR_ACCESS_DENIED;

  if(fdc.fd==0){
    char file_name[MAX_PATH_CEPH];
    wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
    ToLinuxFilePath(file_name);

    fwprintf(stderr, L"ceph_write reopen fd [fn:%ls][Offset=%ld]\n",FileName, Offset);

    int fd_new = ceph_open(cmount, file_name, O_RDONLY, 0);
    if(fd_new < 0)
    {
      fwprintf(stderr, L"ceph_write reopen fd [fn:%ls][fd_new=%d][Offset=%ld]\n", FileName, fd_new, Offset);
      return -1;
    }

    int ret = ceph_write(cmount, fd_new, Buffer, NumberOfBytesToWrite, Offset);
    if(ret<0)
    {
      fwprintf(stderr, L"ceph_write IO error [fn:%ls][fd=%d][Offset=%lld][Length=%ld]\n", FileName, fd_new, Offset, NumberOfBytesToWrite);
      ceph_close(cmount, fd_new);
      return ret;
    }
    *NumberOfBytesWritten = ret;

    ceph_close(cmount, fd_new);
    return 0;
  }
  else{
    int ret = ceph_write(cmount, fdc.fd, Buffer, NumberOfBytesToWrite, Offset);
    if(ret<0)
    {
      fwprintf(stderr, L"ceph_write IO error [fn:%ls][fd=%d][Offset=%lld][Length=%ld]\n", FileName, fdc.fd, Offset, NumberOfBytesToWrite);
      return ret;
    }
    *NumberOfBytesWritten = ret;

    return 0;
  }
}


static int
WinCephFlushFileBuffers(
  LPCWSTR    FileName,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];

  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"FlushFileBuffers : %ls\n", filePath);

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));
  if(fdc.fd==0){
    fwprintf(stderr, L"ceph_sync FD error [%ls] fdc is NULL\n", FileName);
    return -1;
  }

  int ret = ceph_fsync(cmount, fdc.fd, 0);
  if(ret){
    fwprintf(stderr, L"ceph_sync error [%ls][%df]\n", FileName, fdc.fd);
    return -1;
  }

  return 0;
}

static int
WinCephGetFileInformation(
  LPCWSTR              FileName,
  LPBY_HANDLE_FILE_INFORMATION  HandleFileInformation,
  PDOKAN_FILE_INFO        DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"GetFileInfo : %ls\n", filePath);

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  memset(HandleFileInformation, 0, sizeof(BY_HANDLE_FILE_INFORMATION));

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  struct stat stbuf;
  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));
  if (fdc.fd==0) {
    int ret = ceph_stat(cmount, file_name, &stbuf);
    if(ret){
      DbgPrintW(L"GetFileInformation ceph_stat error [%ls]\n", FileName);
      return -1;
    }
  }else{
    int ret = ceph_fstat(cmount, fdc.fd, &stbuf);
    if(ret){
      fwprintf(stderr, L"GetFileInformation ceph_fstat error [%ls]\n", FileName);
      return -1;
    }
  }

  DbgPrintW(L"GetFileInformation1 [%ls][size:%lld][time:%lld]\n",
    FileName, stbuf.st_size, stbuf.st_mtime);
  //fill stbuf.st_size
  HandleFileInformation->nFileSizeLow = (stbuf.st_size << 32)>>32;
  HandleFileInformation->nFileSizeHigh = stbuf.st_size >> 32;

  //fill stbuf.st_mtim
  UnixTimeToFileTime(stbuf.st_mtime, &HandleFileInformation->ftCreationTime);
  UnixTimeToFileTime(stbuf.st_mtime, &HandleFileInformation->ftLastAccessTime);
  UnixTimeToFileTime(stbuf.st_mtime, &HandleFileInformation->ftLastWriteTime);

  DbgPrintW(L"GetFileInformation6 [%ls][size:%lld][time a:%lld m:%lld c:%lld]\n",
    FileName, stbuf.st_size, stbuf.st_atime, stbuf.st_mtime, stbuf.st_ctime);

  //fill stbuf.st_mode
  if(S_ISDIR(stbuf.st_mode)){
    DbgPrintW(L"[%ls] is a Directory.............\n", FileName);
    HandleFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
  }
  else if(S_ISREG(stbuf.st_mode)){
    DbgPrintW(L"[%ls] is a Regular File.............\n", FileName);
    HandleFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;
  }

  //fill stbuf.st_ino
  HandleFileInformation->nFileIndexLow = (stbuf.st_ino << 32)>>32;
  HandleFileInformation->nFileIndexHigh = stbuf.st_ino >> 32;

  //fill stbuf.st_nlink
  HandleFileInformation->nNumberOfLinks = stbuf.st_nlink;

  return 0;
}

static int
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

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

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
      return -ERROR_ACCESS_DENIED;
  }

  struct ceph_dir_result *dirp;
  int ret = ceph_opendir(cmount, file_name, &dirp);
  if(ret != 0){
    fwprintf(stderr, L"ceph_opendir error : %ls [%d]\n", FileName, ret);
    return -1;
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
      return ret;
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
    UnixTimeToFileTime(stbuf.stx_mtime.tv_sec, &findData.ftCreationTime);
    UnixTimeToFileTime(stbuf.stx_mtime.tv_sec, &findData.ftLastAccessTime);
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


static int
WinCephDeleteFile(
  LPCWSTR        FileName,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"DeleteFile %ls\n", filePath);

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  if(g_UseACL)
  {
    /* permission check*/
    int st = permission_walk_parent(cmount, file_name, g_UID, g_GID,
                    PERM_WALK_CHECK_WRITE|PERM_WALK_CHECK_EXEC);
    if(st)
      return -ERROR_ACCESS_DENIED;
  }

  DbgPrintW(L"ceph_unlink [%ls]\n", FileName);
  return 0;
}

static int
WinCephDeleteDirectory(
  LPCWSTR        FileName,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];
  WIN32_FIND_DATAW findData;

  ZeroMemory(filePath, sizeof(filePath));
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"DeleteDirectory %ls\n", filePath);

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

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
      return -ERROR_ACCESS_DENIED;
  }

  struct ceph_dir_result *dirp;
  int ret = ceph_opendir(cmount, file_name, &dirp);
  if(ret != 0){
    fwprintf(stderr, L"ceph_opendir error : %ls [%d]\n", FileName, ret);
    return -1;
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
        return -(int)ERROR_DIR_NOT_EMPTY;
      }
    }else break;
  }

  ceph_closedir(cmount, dirp);
  return 0;
}


static int
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

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

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
      return -ERROR_ACCESS_DENIED;
  }

  int ret = ceph_rename(cmount, file_name, newfile_name);
  if(ret){
    DbgPrint("\terror code = %d\n\n", ret);
    return ret;
  }
  return ret;
}


static int
WinCephLockFile(
  LPCWSTR        FileName,
  LONGLONG      ByteOffset,
  LONGLONG      Length,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  // TODO: this is a stub at the moment.
  fwprintf(stderr, L"LockFile (unimplemented) %ls [offset:%lld][len:%lld]\n", filePath,ByteOffset,Length);

  return 0;
}


static int
WinCephSetEndOfFile(
  LPCWSTR        FileName,
  LONGLONG      ByteOffset,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR      filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);
  DbgPrintW(L"SetEndOfFile %ls, %I64d\n", filePath, ByteOffset);

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));
  if (fdc.fd==0) {
    DbgPrintW(L"\tinvalid handle\n\n");
    fwprintf(stderr, L"SetEndOfFile fdc is NULL [%ls]\n", FileName);
    return -1;
  }

  DbgPrintW(L"SetEndOfFile [%ls][%d][ByteOffset:%lld]\n", FileName, fdc.fd, ByteOffset);

  int ret = ceph_ftruncate(cmount, fdc.fd, ByteOffset);
  if(ret){
    fwprintf(stderr, L"SetEndOfFile ceph_ftruncate error [%ls][%d][ByteOffset:%lld]\n", FileName, ret, ByteOffset);
    return -1;
  }

  return 0;
}

static int
WinCephSetAllocationSize(
  LPCWSTR           FileName,
  LONGLONG          AllocSize,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR      filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  DbgPrintW(L"SetAllocationSize %ls, %I64d\n", filePath, AllocSize);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  struct fd_context fdc;
  memcpy(&fdc, &(DokanFileInfo->Context), sizeof(fdc));
  if (fdc.fd==0) {
    fwprintf(stderr, L"SetAllocationSize fdc is NULL [%ls]\n", FileName);
    return -1;
  }

  fwprintf(stderr, L"SetAllocationSize [%ls][%d][AllocSize:%lld]\n", FileName, fdc.fd, AllocSize);

  struct stat stbuf;
  int ret = ceph_fstat(cmount, fdc.fd, &stbuf);
  if(ret){
    fwprintf(stderr, L"SetAllocationSize ceph_stat error [%ls][%d][AllocSize:%lld]\n", FileName, ret, AllocSize);
    return -1;
  }

  if(AllocSize < stbuf.st_size){
    int ret = ceph_ftruncate(cmount, fdc.fd, AllocSize);
    if(ret){
      fwprintf(stderr, L"SetAllocationSize ceph_ftruncate error [%ls][%d][AllocSize:%lld]\n", FileName, ret, AllocSize);
      return -1;
    }

    return 0;
  }
  else{
    DbgPrintW(L"SetAllocationSize ceph_ftruncate EQUAL no need [%ls][%d][AllocSize:%lld]\n", FileName, ret, AllocSize);
  }

  return 0;
}


static int
WinCephSetFileAttributes(
  LPCWSTR       FileName,
  DWORD         FileAttributes,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  DbgPrintW(L"SetFileAttributes [%ls][%d]\n", FileName, FileAttributes);

  return 0;
}


static int
WinCephSetFileTime(
  LPCWSTR        FileName,
  CONST FILETIME*    CreationTime,
  CONST FILETIME*    LastAccessTime,
  CONST FILETIME*    LastWriteTime,
  PDOKAN_FILE_INFO     DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"SetFileTime %ls\n", filePath);

  // TODO: make this configurable.

  /*
    SetFileTime Call has some bug on Microsoft Office programs.
    So Just Comment these code . Need to FIX!!!
  */

  //DokanResetTimeout(CEPH_DOKAN_IO_TIMEOUT, DokanFileInfo);

  //char file_name[MAX_PATH_CEPH];
  //wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  //ToLinuxFilePath(file_name);

  //struct stat stbuf;
  //memset(&stbuf, 0, sizeof(stbuf));
  //
  //int mask = 0;
  //if(CreationTime != NULL)
  //{
  //  mask |= CEPH_SETATTR_MTIME;
  //  FileTimeToUnixTime(*LastWriteTime, &stbuf.st_mtim.tv_sec);
  //}
  //if(LastAccessTime != NULL)
  //{
  //  mask |= CEPH_SETATTR_ATIME;
  //  FileTimeToUnixTime(*LastAccessTime, &stbuf.st_atim.tv_sec);
  //}
  //if(LastWriteTime != NULL)
  //{
  //  mask |= CEPH_SETATTR_MTIME;
  //  FileTimeToUnixTime(*LastWriteTime, &stbuf.st_mtim.tv_sec);
  //}

  //fwprintf(stderr, L"SetFileTime [%ls][st_atim:%lld][st_mtim:%lld]\n", FileName, stbuf.st_atim.tv_sec, stbuf.st_mtim.tv_sec);
  //
  //int ret = ceph_setattr(cmount, file_name, &stbuf, mask);
  //if(ret){
  //  fwprintf(stderr, L"SetFileTime ceph_setattr error [%ls]\n", FileName);
  //  return -1;
  //}
  return 0;
}

static int
WinCephUnlockFile(
  LPCWSTR        FileName,
  LONGLONG      ByteOffset,
  LONGLONG      Length,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  // TODO: implement this stub. If needed, we can make it optional.
  fwprintf(stderr, L"UnlockFile (unimplemented) %ls [offset:%lld][len:%lld]\n", filePath,ByteOffset,Length);

  return 0;
}

static int
WinCephGetFakeFileSecurity(
  LPCWSTR          FileName,
  PSECURITY_INFORMATION  SecurityInformation,
  PSECURITY_DESCRIPTOR  SecurityDescriptor,
  ULONG        BufferLength,
  PULONG        LengthNeeded,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  HANDLE  handle;
  WCHAR   filePath[MAX_PATH_CEPH];
  BOOL    opened = FALSE;

  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"GetFileSecurity %ls\n", filePath);

  char file_name[MAX_PATH_CEPH];
  wchar_to_char(file_name, FileName, MAX_PATH_CEPH);
  ToLinuxFilePath(file_name);

  struct stat stbuf;
  int ret = ceph_stat(cmount, file_name, &stbuf);
  if(ret){
    fwprintf(stderr, L"GetFileSecurity ceph_stat error [%ls]\n", FileName);
    return 0;
  }

  if(S_ISREG(stbuf.st_mode))
  {
    handle = CreateFile(
      Wceph_conf_file,
      GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
      FILE_SHARE_READ|FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      0,
      NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DbgPrintW(L"\tCreateFile error : %d\n\n", GetLastError());
      return -1;
    }
    opened = TRUE;
  }
  else if(S_ISDIR(stbuf.st_mode))
  {
    handle = CreateFile(
      L".",
      GENERIC_READ|GENERIC_EXECUTE,
      FILE_SHARE_READ,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS,
      NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DbgPrintW(L"\tCreateFile error : %d\n\n", GetLastError());
      return -1;
    }
    opened = TRUE;
  }
  else
    return 0;

  if(*SecurityInformation & SACL_SECURITY_INFORMATION != 0)
    *SecurityInformation &= (~SACL_SECURITY_INFORMATION);
  if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor,
      BufferLength, LengthNeeded)) {
    int error = GetLastError();
    if (error == ERROR_INSUFFICIENT_BUFFER) {
      DbgPrintW(L"  GetUserObjectSecurity failed: ERROR_INSUFFICIENT_BUFFER\n");
      if (opened)
        CloseHandle(handle);
      return error * -1;
    } else {
      fwprintf(stderr, L"  GetUserObjectSecurity failed: [err=%d][%ld]\n", error, *SecurityInformation);
      if (opened)
        CloseHandle(handle);
      return error * -1;
    }
  }

  if (opened)
    CloseHandle(handle);

  return 0;
}

static int
WinCephGetFileSecurity(
  LPCWSTR          FileName,
  PSECURITY_INFORMATION  SecurityInformation,
  PSECURITY_DESCRIPTOR  SecurityDescriptor,
  ULONG        BufferLength,
  PULONG        LengthNeeded,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR  filePath[MAX_PATH_CEPH];
  GetFilePath(filePath, MAX_PATH_CEPH, FileName);

  DbgPrintW(L"GetFileSecurity %ls\n", filePath);

  return WinCephGetFakeFileSecurity(FileName, SecurityInformation,
      SecurityDescriptor, BufferLength, LengthNeeded, DokanFileInfo);
}

static int
WinCephSetFileSecurity(
  LPCWSTR          FileName,
  PSECURITY_INFORMATION  SecurityInformation,
  PSECURITY_DESCRIPTOR  SecurityDescriptor,
  ULONG        SecurityDescriptorLength,
  PDOKAN_FILE_INFO  DokanFileInfo)
{
  WCHAR filePath[MAX_PATH_CEPH];

  GetFilePath(filePath, MAX_PATH_CEPH, FileName);
  DbgPrintW(L"SetFileSecurity %ls\n", filePath);

  return 0;
}

static int
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

static int
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
    return -1;
  }

  *FreeBytesAvailable   = vfsbuf.f_bsize * vfsbuf.f_bfree;
  *TotalNumberOfBytes   = vfsbuf.f_bsize * vfsbuf.f_blocks;
  *TotalNumberOfFreeBytes = vfsbuf.f_bsize * vfsbuf.f_bfree;

  return 0;
}


static int
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

  if(argc==2)
  {
    if(strcmp(argv[1], "--version")==0 || strcmp(argv[1], "-v")==0)
    {
      ceph_show_version();
      return 0;
    }
  }

  if (argc < 5) {
    ceph_show_version();
    fprintf(stderr, "ceph-dokan.exe\n"
      "  -c CephConfFile  (ex. /r c:\\ceph.conf)\n"
      "  -l DriveLetter (ex. /l m)\n"
      "  -t ThreadCount (ex. /t 5)\n"
      "  -d (enable debug output)\n"
      "  -s (use stderr for output)\n"
      "  -m (use removable drive)\n"
      "  -u Uid (use uid)\n"
      "  -g Gid (use gid)\n"
      "  -a (use posix acl)\n"
      "  -x sub_mount_path\n"
      );
    return -1;
  }

  ceph_show_version();

  if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE)) {
    fwprintf(stderr, L"Unable to install handler!\n");
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
      //wcscpy_s(MountPoint, sizeof(MountPoint)/sizeof(WCHAR), argv[command]);
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
    case L'm':
      dokanOptions->Options |= DOKAN_OPTION_REMOVABLE;
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
    default:
      fwprintf(stderr, L"unknown command: %ls\n", wargv[command]);
      return -1;
    }
  }

  if (g_DebugMode) {
    dokanOptions->Options |= DOKAN_OPTION_DEBUG;
  }
  if (g_UseStdErr) {
    dokanOptions->Options |= DOKAN_OPTION_STDERR;
  }

  ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
  dokanOperations->ZwCreateFile = WinCephCreateFile;
  dokanOperations->Cleanup = WinCephCleanup;
  dokanOperations->CloseFile = WinCephCloseFile;
  dokanOperations->ReadFile = WinCephReadFile;
  dokanOperations->WriteFile = WinCephWriteFile;
  dokanOperations->FlushFileBuffers = WinCephFlushFileBuffers;
  dokanOperations->GetFileInformation = WinCephGetFileInformation;
  dokanOperations->FindFiles = WinCephFindFiles;
  dokanOperations->FindFilesWithPattern = NULL;
  dokanOperations->SetFileAttributes = WinCephSetFileAttributes;
  dokanOperations->SetFileTime = WinCephSetFileTime;
  dokanOperations->DeleteFile = WinCephDeleteFile;
  dokanOperations->DeleteDirectory = WinCephDeleteDirectory;
  dokanOperations->MoveFile = WinCephMoveFile;
  dokanOperations->SetEndOfFile = WinCephSetEndOfFile;
  dokanOperations->SetAllocationSize = WinCephSetAllocationSize;
  dokanOperations->LockFile = WinCephLockFile;
  dokanOperations->UnlockFile = WinCephUnlockFile;
  dokanOperations->GetFileSecurity = WinCephGetFileSecurity;
  dokanOperations->SetFileSecurity = WinCephSetFileSecurity;
  dokanOperations->GetDiskFreeSpace = NULL;
  dokanOperations->GetVolumeInformation = WinCephGetVolumeInformation;
  dokanOperations->Unmounted = WinCephUnmount;
  dokanOperations->GetDiskFreeSpace = WinCephGetDiskFreeSpace;

  //init socket
  WORD VerNum = MAKEWORD(2, 2);
  WSADATA VerData;
  if (WSAStartup(VerNum, &VerData) != 0) {
    fprintf(stderr, "FAILED to init winsock!!!\n");
    return -1;
  }

  //ceph_mount
  int ret = 0;
  ceph_create(&cmount, NULL);
  ret = ceph_conf_read_file(cmount, ceph_conf_file);
  if(ret)
  {
    fprintf(stderr, "ceph_conf_read_file error!\n");
    return ret;
  }
  fprintf(stderr, "ceph_conf_read_file OK\n");

  ret = ceph_mount(cmount, sub_mount_path);
  if(ret)
  {
    fprintf(stderr, "ceph_mount error!\n");
    return ret;
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

