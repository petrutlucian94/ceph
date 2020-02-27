/*
    Virtual Disk Driver over HTTP.
    Copyright (C) 2006-2015 Bo Brantén.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef HTTPDISK_H
#define HTTPDISK_H

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef __T
#ifdef _NTDDK_
#define __T(x)  L ## x
#else
#define __T(x)  x
#endif
#endif

#ifndef _T
#define _T(x)   __T(x)
#endif

#define DEVICE_BASE_NAME    _T("\\HttpDisk")
#define DEVICE_DIR_NAME     _T("\\Device")      DEVICE_BASE_NAME
#define DEVICE_NAME_PREFIX  DEVICE_DIR_NAME     _T("\\Http")

#define IOCTL_HTTP_DISK_CONNECT     CTL_CODE(FILE_DEVICE_DISK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_HTTP_DISK_DISCONNECT  CTL_CODE(FILE_DEVICE_DISK, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_SET_SOCK   CTL_CODE(FILE_DEVICE_DISK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_SET_BLKSIZE   CTL_CODE(FILE_DEVICE_DISK, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_SET_SIZE  CTL_CODE(FILE_DEVICE_DISK, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_DO_IT  CTL_CODE(FILE_DEVICE_DISK, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_CLEAR_SOCK  CTL_CODE(FILE_DEVICE_DISK, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_CLEAR_QUEUE  CTL_CODE(FILE_DEVICE_DISK, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_PRINT_DEBUG  CTL_CODE(FILE_DEVICE_DISK, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_SET_SIZE_BLOCKS  CTL_CODE(FILE_DEVICE_DISK, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_DISCONNECT  CTL_CODE(FILE_DEVICE_DISK, 0x810, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_SET_TIMEOUT  CTL_CODE(FILE_DEVICE_DISK, 0x811, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_SET_FLAGS  CTL_CODE(FILE_DEVICE_DISK, 0x812, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_NBD_SET_READ_ONLY  CTL_CODE(FILE_DEVICE_DISK, 0x813, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef struct _HTTP_DISK_INFORMATION {
    ULONG   Address;
    USHORT  Port;
    UCHAR   DriveLetter;
    USHORT  HostNameLength;
    CHAR    HostName[256];
    USHORT  PortNameLength;
    CHAR    PortName[256];
    USHORT  ExportNameLength;
    CHAR    ExportName[256];
    USHORT  FileNameLength;
    CHAR    FileName[1];
} HTTP_DISK_INFORMATION, *PHTTP_DISK_INFORMATION;

#ifdef _MSC_VER
#define PACK( DECL ) __pragma( pack(push, 1) ) DECL __pragma( pack(pop))
#endif

#if defined(__cplusplus)
	}
#endif
#endif /* HTTPDISK_H */
