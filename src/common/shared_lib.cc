#include "shared_lib.h"


#if defined(_WIN32)
shared_lib_handle_t shared_lib_open(const char *filename) {
  return LoadLibrary(filename);
}

shared_lib_handle_t shared_lib_open(const char *filename, int flags) {
  return LoadLibrary(filename);
}

int shared_lib_close(shared_lib_handle_t handle) {
  //FreeLibrary returns 0 on error, as opposed to dlclose.
  return !FreeLibrary(handle);
}

void* shared_lib_find_symbol(shared_lib_handle_t handle, const char* symbol) {
  return (void*)GetProcAddress(handle, symbol);
}

char* shared_lib_last_err() {
  // As opposed to dlerror messages, this has to be freed.
  DWORD err_code = ::GetLastError();
  LPSTR msg = NULL;
  FormatMessageA(
    FORMAT_MESSAGE_ALLOCATE_BUFFER |
    FORMAT_MESSAGE_FROM_SYSTEM |
    FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    err_code,
    0,
    (LPSTR) &msg,
    0,
    NULL);
    return msg;
}

void shared_lib_free_err_msg(char* msg) {
  LocalFree(msg);
}

#else
shared_lib_handle_t shared_lib_open(const char *filename) {
  return dlopen(filename, RTLD_NOW);
}

shared_lib_handle_t shared_lib_open(const char *filename, int flags) {
  return dlopen(filename, RTLD_NOW | flags);
}

int shared_lib_close(shared_lib_handle_t handle) {
  return dlclose(handle);
}

void* shared_lib_find_symbol(shared_lib_handle_t handle, const char* symbol) {
  return dlsym(handle, symbol);
}

char* shared_lib_last_err() {
  return dlerror();
}

void shared_lib_free_err_msg(char* msg) {
  // This buffer doesn't need to be deallocated.
}

#endif /* _WIN32 */

void shared_lib_print_last_err(std::ostream *ss) {
  char* last_err = shared_lib_last_err();
  *ss << last_err;
  shared_lib_free_err_msg(last_err);
}
