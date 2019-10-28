#include "common/xattr.h"

#include <errno.h>

int ceph_os_setxattr(const char *path, const char *name,
                     const void *value, size_t size) {
    errno = EOPNOTSUPP;
    return -1;
}
int ceph_os_fsetxattr(int fd, const char *name, const void *value,
                   size_t size) {
    errno = EOPNOTSUPP;
    return -1;
}
ssize_t ceph_os_getxattr(const char *path, const char *name,
                         void *value, size_t size) {
    errno = EOPNOTSUPP;
    return -1;
}
ssize_t ceph_os_fgetxattr(int fd, const char *name, void *value,
                          size_t size) {
    errno = EOPNOTSUPP;
    return -1;
}
ssize_t ceph_os_listxattr(const char *path, char *list, size_t size) {
    errno = EOPNOTSUPP;
    return -1;
}
ssize_t ceph_os_flistxattr(int fd, char *list, size_t size) {
    errno = EOPNOTSUPP;
    return -1;
}
int ceph_os_removexattr(const char *path, const char *name) {
    errno = EOPNOTSUPP;
    return -1;
}
int ceph_os_fremovexattr(int fd, const char *name) {
    errno = EOPNOTSUPP;
    return -1;
}
