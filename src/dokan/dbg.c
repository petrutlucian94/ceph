#include "dbg.h"

#include <stdio.h>
#include <stdlib.h>

void DbgPrintW(LPCWSTR format, ...)
{
  if (g_DebugMode) {
    WCHAR buffer[512];
    va_list argp;
    va_start(argp, format);
    vswprintf(buffer, 512, format, argp);
    va_end(argp);
    if (g_UseStdErr) {
      fwprintf(stderr, buffer);
    } else {
      OutputDebugStringW(buffer);
    }
  }
}

void DbgPrint(char* format, ...)
{
  if (g_DebugMode) {
    char buffer[512];
    va_list argp;
    va_start(argp, format);
    vsprintf(buffer, format, argp);
    va_end(argp);
    if (g_UseStdErr) {
      fprintf(stderr, "%s", buffer);
    } else {
      OutputDebugString(buffer);
    }
  }
}

void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo)
{
  HANDLE handle;
  UCHAR buffer[1024];
  DWORD returnLength;
  WCHAR accountName[256];
  WCHAR domainName[256];
  DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
  DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
  PTOKEN_USER tokenUser;
  SID_NAME_USE snu;

  handle = DokanOpenRequestorToken(DokanFileInfo);
  if (handle == INVALID_HANDLE_VALUE) {
    DbgPrintW(L"  DokanOpenRequestorToken failed\n");
    fwprintf(stderr, L"DokanOpenRequestorToken err %d\n", GetLastError());
    return;
  }

  if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer), &returnLength)) {
    DbgPrintW(L"  GetTokenInformaiton failed: %d\n", GetLastError());
    CloseHandle(handle);
    fwprintf(stderr, L"GetTokenInformation err\n");
    return;
  }

  CloseHandle(handle);

  tokenUser = (PTOKEN_USER)buffer;

  if (!LookupAccountSidW(NULL, tokenUser->User.Sid, accountName,
      &accountLength, domainName, &domainLength, &snu)) {
    DbgPrintW(L"  LookupAccountSid failed: %d\n", GetLastError());
    return;
  }

  DbgPrintW(L"  AccountName: %s, DomainName: %s\n", accountName, domainName);
}

void PrintOpenParams(
  LPCWSTR FilePath,
  ACCESS_MASK AccessMode,
  DWORD FlagsAndAttributes,
  ULONG ShareMode,
  DWORD CreationDisposition,
  ULONG CreateOptions,
  PDOKAN_FILE_INFO DokanFileInfo)
{
  DbgPrintW(L"CreateFile : %ls\n", FilePath);

  if (g_DebugMode) {
    PrintUserName(DokanFileInfo);
  }

  if (CreationDisposition == CREATE_NEW)
    DbgPrintW(L"\tCREATE_NEW\n");
  if (CreationDisposition == OPEN_ALWAYS)
    DbgPrintW(L"\tOPEN_ALWAYS\n");
  if (CreationDisposition == CREATE_ALWAYS)
    DbgPrintW(L"\tCREATE_ALWAYS\n");
  if (CreationDisposition == OPEN_EXISTING)
    DbgPrintW(L"\tOPEN_EXISTING\n");
  if (CreationDisposition == TRUNCATE_EXISTING)
    DbgPrintW(L"\tTRUNCATE_EXISTING\n");

  DbgPrintW(L"\tShareMode = 0x%x\n", ShareMode);

  WinCephCheckFlag(ShareMode, FILE_SHARE_READ);
  WinCephCheckFlag(ShareMode, FILE_SHARE_WRITE);
  WinCephCheckFlag(ShareMode, FILE_SHARE_DELETE);

  DbgPrintW(L"\tAccessMode = 0x%x\n", AccessMode);

  WinCephCheckFlag(AccessMode, GENERIC_READ);
  WinCephCheckFlag(AccessMode, GENERIC_WRITE);
  WinCephCheckFlag(AccessMode, GENERIC_EXECUTE);

  WinCephCheckFlag(AccessMode, WIN32_DELETE);
  WinCephCheckFlag(AccessMode, FILE_READ_DATA);
  WinCephCheckFlag(AccessMode, FILE_READ_ATTRIBUTES);
  WinCephCheckFlag(AccessMode, FILE_READ_EA);
  WinCephCheckFlag(AccessMode, READ_CONTROL);
  WinCephCheckFlag(AccessMode, FILE_WRITE_DATA);
  WinCephCheckFlag(AccessMode, FILE_WRITE_ATTRIBUTES);
  WinCephCheckFlag(AccessMode, FILE_WRITE_EA);
  WinCephCheckFlag(AccessMode, FILE_APPEND_DATA);
  WinCephCheckFlag(AccessMode, WRITE_DAC);
  WinCephCheckFlag(AccessMode, WRITE_OWNER);
  WinCephCheckFlag(AccessMode, SYNCHRONIZE);
  WinCephCheckFlag(AccessMode, FILE_EXECUTE);
  WinCephCheckFlag(AccessMode, STANDARD_RIGHTS_READ);
  WinCephCheckFlag(AccessMode, STANDARD_RIGHTS_WRITE);
  WinCephCheckFlag(AccessMode, STANDARD_RIGHTS_EXECUTE);

  DbgPrintW(L"\tFlagsAndAttributes = 0x%x\n", FlagsAndAttributes);

  WinCephCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_ARCHIVE);
  WinCephCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_ENCRYPTED);
  WinCephCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_HIDDEN);
  WinCephCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_NORMAL);
  WinCephCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
  WinCephCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_OFFLINE);
  WinCephCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_READONLY);
  WinCephCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_SYSTEM);
  WinCephCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_TEMPORARY);
  WinCephCheckFlag(FlagsAndAttributes, FILE_FLAG_WRITE_THROUGH);
  WinCephCheckFlag(FlagsAndAttributes, FILE_FLAG_OVERLAPPED);
  WinCephCheckFlag(FlagsAndAttributes, FILE_FLAG_NO_BUFFERING);
  WinCephCheckFlag(FlagsAndAttributes, FILE_FLAG_RANDOM_ACCESS);
  WinCephCheckFlag(FlagsAndAttributes, FILE_FLAG_SEQUENTIAL_SCAN);
  WinCephCheckFlag(FlagsAndAttributes, FILE_FLAG_DELETE_ON_CLOSE);
  WinCephCheckFlag(FlagsAndAttributes, FILE_FLAG_BACKUP_SEMANTICS);
  WinCephCheckFlag(FlagsAndAttributes, FILE_FLAG_POSIX_SEMANTICS);
  WinCephCheckFlag(FlagsAndAttributes, FILE_FLAG_OPEN_REPARSE_POINT);
  WinCephCheckFlag(FlagsAndAttributes, FILE_FLAG_OPEN_NO_RECALL);
  WinCephCheckFlag(FlagsAndAttributes, SECURITY_ANONYMOUS);
  WinCephCheckFlag(FlagsAndAttributes, SECURITY_IDENTIFICATION);
  WinCephCheckFlag(FlagsAndAttributes, SECURITY_IMPERSONATION);
  WinCephCheckFlag(FlagsAndAttributes, SECURITY_DELEGATION);
  WinCephCheckFlag(FlagsAndAttributes, SECURITY_CONTEXT_TRACKING);
  WinCephCheckFlag(FlagsAndAttributes, SECURITY_EFFECTIVE_ONLY);
  WinCephCheckFlag(FlagsAndAttributes, SECURITY_SQOS_PRESENT);

  DbgPrintW(L"DokanFileInfo->IsDirectory = %d\n", DokanFileInfo->IsDirectory);
  DbgPrintW(L"\tCreateOptions = 0x%x\n", CreateOptions);
  WinCephCheckFlag(CreateOptions, FILE_DIRECTORY_FILE);
  WinCephCheckFlag(CreateOptions, FILE_WRITE_THROUGH);
  WinCephCheckFlag(CreateOptions, FILE_SEQUENTIAL_ONLY);
  WinCephCheckFlag(CreateOptions, FILE_NO_INTERMEDIATE_BUFFERING);
  WinCephCheckFlag(CreateOptions, FILE_SYNCHRONOUS_IO_ALERT);
  WinCephCheckFlag(CreateOptions, FILE_SYNCHRONOUS_IO_NONALERT);
  WinCephCheckFlag(CreateOptions, FILE_NON_DIRECTORY_FILE);
  WinCephCheckFlag(CreateOptions, FILE_CREATE_TREE_CONNECTION);
  WinCephCheckFlag(CreateOptions, FILE_COMPLETE_IF_OPLOCKED);
  WinCephCheckFlag(CreateOptions, FILE_NO_EA_KNOWLEDGE);
  WinCephCheckFlag(CreateOptions, FILE_OPEN_REMOTE_INSTANCE);
  WinCephCheckFlag(CreateOptions, FILE_RANDOM_ACCESS);
  WinCephCheckFlag(CreateOptions, FILE_DELETE_ON_CLOSE);
  WinCephCheckFlag(CreateOptions, FILE_OPEN_BY_FILE_ID);
  WinCephCheckFlag(CreateOptions, FILE_OPEN_FOR_BACKUP_INTENT);
  WinCephCheckFlag(CreateOptions, FILE_NO_COMPRESSION);
  WinCephCheckFlag(CreateOptions, FILE_OPEN_REQUIRING_OPLOCK);
  WinCephCheckFlag(CreateOptions, FILE_DISALLOW_EXCLUSIVE);
  WinCephCheckFlag(CreateOptions, FILE_RESERVE_OPFILTER);
  WinCephCheckFlag(CreateOptions, FILE_OPEN_REPARSE_POINT);
  WinCephCheckFlag(CreateOptions, FILE_OPEN_NO_RECALL);
  WinCephCheckFlag(CreateOptions, FILE_OPEN_FOR_FREE_SPACE_QUERY);
}
