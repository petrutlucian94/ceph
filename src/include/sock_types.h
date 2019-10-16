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

// afunix.h is available starting with Windows SDK 17063. Still, it wasn't
// picked up by mingw yet, for which reason we're going to define sockaddr_un
// here.
#ifndef _AFUNIX_
#define UNIX_PATH_MAX 108

typedef struct sockaddr_un
{
     ADDRESS_FAMILY sun_family;     /* AF_UNIX */
     char sun_path[UNIX_PATH_MAX];  /* pathname */
} SOCKADDR_UN, *PSOCKADDR_UN;

#define SIO_AF_UNIX_GETPEERPID _WSAIOR(IOC_VENDOR, 256)
#endif /* _AFUNIX */

#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

#endif /* __CEPH_SOCKTYPES_H */
