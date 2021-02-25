#include "include/compat.h"

void UnixTimeToFileTime(time_t t, LPFILETIME pft);
void FileTimeToUnixTime(FILETIME ft, time_t *t);

std::wstring to_wstring(const std::string& str);
std::string to_string(const std::wstring& str);
