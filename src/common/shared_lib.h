// This provides a portable way of consuming shared libraries,
// staying as close as possible to dlopen semantics.

#ifndef SHARED_LIB_H_
#define SHARED_LIB_H_

#ifdef _WIN32
  #include "include/compat.h"

  typedef HMODULE lib_handle;
#else
  typedef void* lib_handle;
#endif /* _WIN32 */


lib_handle open_shared_lib(const char *filename);
// Similar to dlclose and unlike FreeLibrary, this returns 0
// on success.
int close_shared_lib(lib_handle handle);
// Returns a string describing the most recent error.
// Uses dlerror on Posix compliant platforms and GetLastError
// on Windows.
char* shared_lib_last_err();
// As opposed to dlerror messages, those buffers will have to be
// deallocated on Windows.
void shared_lib_free_err_msg(char* msg);
void shared_lib_print_last_err(std::ostream *ss);
void* find_symbol(lib_handle handle, const char* symbol);

#endif /* SHARED_LIB_H_ */
