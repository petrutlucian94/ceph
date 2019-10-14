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
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

#endif /* __CEPH_SOCKTYPES_H */
