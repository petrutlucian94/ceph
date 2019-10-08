// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (c) 2019 SUSE LLC
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#ifndef WINDEFS_H
#define WINDEFS_H 1

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

#endif /* windefs.h */
