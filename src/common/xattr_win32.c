#include <errno.h>

#include "common/xattr.h"
#include "include/compat.h"

// The Windows headers allocate MAX_PATH + 36 characters
#define STREAM_MAX_PATH = MAX_PATH + 36;

HANDLE open_stream(const char *path, const char *name, int desired_access,
                   int create_disposition) {
  char stream_path[MAX_PATH];
  snprintf(stream_path, "%s:%s", MAX_PATH, path, name);

  HANDLE handle = CreateFileA(
    stream_path,
    desired_access,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL,
    create_disposition,
    FILE_ATTRIBUTE_NORMAL,
    NULL);
  return handle;
}

BOOL file_exists(const char* path) {
  DWORD attributes = GetFileAttributesA(path);

  return (attributes != INVALID_FILE_ATTRIBUTES &&
         !(attributes & FILE_ATTRIBUTE_DIRECTORY));
}

DWORD get_path_by_fd(int fd, char* path, int size) {
  HANDLE handle = (HANDLE*)_get_osfhandle(fd);
  if (handle == INVALID_HANDLE_VALUE) {
    errno = EINVAL;
    return -1;
  }

  if (!GetFinalPathNameByHandleA(handle, path, size,
                                 FILE_NAME_NORMALIZED)) {
    return -1;
  }

  return 0;
}

int ceph_os_setxattr(const char *path, const char *name,
                     const void *value, size_t size) {
  if (!file_exists(path)) {
    errno = ENOENT;
    return -1;
  }

  HANDLE handle = open_stream(path, name, GENERIC_WRITE, CREATE_ALWAYS);
  if (handle == INVALID_HANDLE_VALUE) {
    errno = EINVAL;
    return -1;
  }

  DWORD bytes_written = 0;
  if (!WriteFile(handle, value, size, &bytes_written, NULL)) {
    errno = EPERM;
    return -1;
  }

  return 0;
}

int ceph_os_fsetxattr(int fd, const char *name, const void *value,
                      size_t size) {
  char path[MAX_PATH];
  int err = get_path_by_fd(fd, path, MAX_PATH);
  if (err) {
    return err;
  }

  return ceph_os_setxattr(path, name, value, size);
}

ssize_t ceph_os_getxattr(const char *path, const char *name,
                         void *value, size_t size) {
  if (!file_exists(path)) {
    errno = ENOENT;
    return -1;
  }

  HANDLE handle = open_stream(path, name, GENERIC_READ, OPEN_EXISTING);
  if (handle == INVALID_HANDLE_VALUE) {
    errno = ENODATA;
    return -1;
  }

  LARGE_INTEGER stream_size;
  if (!GetFileSizeEx(handle, &stream_size)) {
    errno = EPERM;
    return -1;
  }

  if (stream_size.QuadPart > size) {
    errno = ERANGE;
    return -1;
  }

  DWORD bytes_read = 0;
  if (!ReadFile(handle, value, size, bytes_read, NULL)) {
    return -1;
  }
}

ssize_t ceph_os_fgetxattr(int fd, const char *name, void *value,
                          size_t size) {
  char path[MAX_PATH];
  int err = get_path_by_fd(fd, path, MAX_PATH);
  if (err) {
    return err;
  }

  return ceph_os_getxattr(path, name, value, size);
}

ssize_t ceph_os_listxattr(const char *path, char *list, size_t size) {
  WIN32_FIND_STREAM_DATA stream_data;
  HANDLE find_h = FindFirstStreamW(
    path, FindStreamInfoStandard, &stream_data, 0);
  if (find_h == INVALID_HANDLE_VALUE) {
    errno = EINVAL;
    return -1;
  }

  int ret_val = 0, offset = 0;
  while (1) {
    int written = snprintf(list + offset, size - offset, "%ws\0",
                           stream_data.cStreamName);
    if (written < 0)
      goto ERR;
    if (written > size - offset) {
      errno = ERANGE;
      goto ERR;
    }

    offset += written;

    if (!FindNextStreamW(find_h, &stream_data)) {
      if (GetLastError() == ERROR_HANDLE_EOF)
        break;
      goto ERR;
    }
  }

FINALLY:
  FindClose(find_h);
  return ret_val;

ERR:
  if (ret_val >= 0)
    ret_val = -1;

  if (!errno)
    errno = EINVAL;

  goto FINALLY;
}


ssize_t ceph_os_flistxattr(int fd, char *list, size_t size) {
  char path[MAX_PATH];
  int err = (fd, path, MAX_PATH);
  if (err) {
    return err;
  }

  return ceph_os_listxattr(path, list, size);
}

int ceph_os_removexattr(const char *path, const char *name) {
  char stream_path[MAX_PATH];
  snprintf(stream_path, "%s:%s", MAX_PATH, path, name);

  if (!DeleteFile(stream_path)) {
    errno = EPERM;
    return -1;
  }
  return 0;
}

int ceph_os_fremovexattr(int fd, const char *name) {
  char path[MAX_PATH];
  int err = get_path_by_fd(fd, path, MAX_PATH);
  if (err) {
    return err;
  }

  return ceph_os_removexattr(path, name);
}
