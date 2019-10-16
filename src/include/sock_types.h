#ifndef __CEPH_SOCKTYPES_H
#define __CEPH_SOCKTYPES_H

#if defined(__FreeBSD__) || defined(_AIX)
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#ifdef _WIN32
// Boost complains if winsock2.h (or windows.h) is included before asio.hpp.
#ifdef __cplusplus
#include <boost/asio.hpp>
#endif

#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>

#ifndef poll
#define poll WSAPoll
#endif

#else
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#endif /* __CEPH_SOCKTYPES_H */
