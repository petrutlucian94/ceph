#include "utils.h"

#include <boost/locale/encoding_utf.hpp>

using boost::locale::conv::utf_to_utf;

std::wstring to_wstring(const std::string& str)
{
  return utf_to_utf<wchar_t>(str.c_str(), str.c_str() + str.size());
}

std::string to_string(const std::wstring& str)
{
  return utf_to_utf<char>(str.c_str(), str.c_str() + str.size());
}

void UnixTimeToFileTime(time_t t, LPFILETIME pft)
{
  // Note that LONGLONG is a 64-bit value
  LONGLONG ll;

  ll = Int32x32To64(t, 10000000) + 116444736000000000;
  pft->dwLowDateTime = (DWORD)ll;
  pft->dwHighDateTime = ll >> 32;
}

void FileTimeToUnixTime(FILETIME ft, time_t *t)
{
  ULARGE_INTEGER ui;
  ui.LowPart  = ft.dwLowDateTime;
  ui.HighPart = ft.dwHighDateTime;

  *t = (LONGLONG)(ui.QuadPart / 10000000ULL - 11644473600ULL);
}

int wchar_to_char(char *strGBK, LPCWSTR FileName, int strlen)
{
  int len = WideCharToMultiByte(CP_UTF8, 0, FileName, -1, NULL, 0, NULL, NULL);
  if(len > strlen){
    return -1;
  }
  WideCharToMultiByte(CP_UTF8, 0, FileName, -1, strGBK, len, NULL, NULL);

  return 0;
}

int char_to_wchar(LPCWSTR FileName, char *strUtf8, int strlen)
{
  int len = MultiByteToWideChar(CP_UTF8, 0, (LPCTSTR)strUtf8, -1, NULL, 0);
  if(len > strlen){
    return -1;
  }
  MultiByteToWideChar(CP_UTF8, 0, (LPCTSTR)strUtf8, -1, FileName, len);

  return 0;
}

void ToLinuxFilePath(char* filePath)
{
  int i;
  for(i = 0; i<strlen(filePath); i++) {
    if( filePath[i] == '\\' ) filePath[i] = '/';
  }
}
