// Various helpers used for debugging purposes, such as functions
// logging certain flags. Since those can be rather verbose, it's
// better if we keep them separate.

#include "include/compat.h"

#include <dokan.h>

extern BOOL g_UseStdErr;
extern BOOL g_DebugMode;

void DbgPrint(char* format, ...);
void DbgPrintW(LPCWSTR format, ...);

#define WinCephCheckFlag(val, flag) if (val&flag) { DbgPrintW(L"\t" #flag L"\n"); }

void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo);
void PrintOpenParams(
  LPCWSTR FilePath,
  ACCESS_MASK AccessMode,
  DWORD FlagsAndAttributes,
  ULONG ShareMode,
  DWORD CreationDisposition,
  ULONG CreateOptions,
  PDOKAN_FILE_INFO DokanFileInfo);