#include "include/compat.h"

void UnixTimeToFileTime(time_t t, LPFILETIME pft);
void FileTimeToUnixTime(FILETIME ft, time_t *t);

int wchar_to_char(char *strGBK, LPCWSTR FileName, int strlen);
int char_to_wchar(LPCWSTR FileName, char *strUtf8, int strlen);

void ToLinuxFilePath(char* filePath);
