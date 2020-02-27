///////////////////////////////////////////////////////////////////////////////
//
//	(C) Copyright 2009-2010 wnbd Open Systems Resources, Inc.
//	All Rights Reserved
//
//  This work is distributed under the wnbd Non-Commercial Software License which is provided
//  at "http://www.wnbdonline.com/page.cfm?name=NonCommLicense" in the hope that it will be
//  enlightening, but WITHOUT ANY WARRANTY; without even the implied warranty of MECHANTABILITY
//
//	wnbd Open Systems Resources, Inc.
//	105 Route 101A Suite 19
//	Amherst, NH 03031  (603) 595-6500 FAX: (603) 595-6503
//
//	MODULE:
//
//		$File: //depot/tools/wnbdvmMEMsample/wnbdVmSampleInc/WNBDVMUserIoctl.h $
//
//	ABSTRACT:
//
//      This h file contains the IOCTL definitions used to communicate
//      with the wnbd Virtual Miniport Driver.
//
//	AUTHOR:
//
//		Open Systems Resources, Inc.
// 
//	REVISION:   
//
//		$Revision: #2 $
//
//
//  NOTE:
//
//      All WCHAR strings used by these IOCTL's are assumed to be Zero 
//      Terminated.
//
//
///////////////////////////////////////////////////////////////////////////////
#ifndef __WNBDVMUSERIOCTL_H__
#define __WNBDVMUSERIOCTL_H__

#if defined(__cplusplus)
extern "C" {
#endif

#define MAX_NAME_LENGTH 256

#include "wnbdvmcfg.h"

#define IOCTL_WNBDVMPORT_SCSIPORT CTL_CODE(FILE_DEVICE_WNBDVMPORT,USER_VM_IOCTL_START,METHOD_BUFFERED,FILE_ALL_ACCESS)

#define IOCTL_WNBDVMPORT_CONNECT  CTL_CODE(FILE_DEVICE_WNBDVMPORT,USER_VM_IOCTL_START+2,METHOD_BUFFERED,FILE_WRITE_ACCESS)

typedef struct _CONNECT_IN {
    COMMAND_IN		Command;
    WCHAR           InstanceName[MAX_NAME_LENGTH];
    WCHAR           Hostname[MAX_NAME_LENGTH];
    WCHAR           PortName[MAX_NAME_LENGTH];
    WCHAR           ExportName[MAX_NAME_LENGTH];
    BOOLEAN         Removable;
    ULONGLONG       DiskSizeMB;
} CONNECT_IN, * PCONNECT_IN;

#define IOCTL_WNBDVMPORT_DISCONNECT CTL_CODE(FILE_DEVICE_WNBDVMPORT,USER_VM_IOCTL_START+3,METHOD_BUFFERED,FILE_WRITE_ACCESS)

//
// USE THE CONNECT_IN structure for DISCONNECT.
//

#define IOCTL_WNBDVMPORT_GETACTIVELIST CTL_CODE(FILE_DEVICE_WNBDVMPORT,USER_VM_IOCTL_START+4,METHOD_BUFFERED,FILE_WRITE_ACCESS)

typedef struct _ACTIVELIST_ENTRY_OUT {

    CONNECT_IN      ConnectionInformation;
    USHORT          Connected;
    USHORT          BusNumber;
    USHORT          TargetId;
    USHORT          Lun;
    USHORT          DiskSizeMB;

} ACTIVELIST_ENTRY_OUT, *PACTIVELIST_ENTRY_OUT;

typedef struct _GETACTIVELIST_OUT {

    ULONG                   ActiveListCount;
    ACTIVELIST_ENTRY_OUT    ActiveEntry[1];

} GETACTIVELIST_OUT, *PGETACTIVELIST_OUT;

#define USER_VM_CREATE	0xA0000001
#define USER_VM_READ	0xA0000002
#define USER_VM_WRITE	0xA0000003
#define USER_VM_FATTRIB 0xA0000004
#define USER_VM_CLOSE	0xA0000005

#if defined(__cplusplus)
}
#endif

#endif //__WNBDVMUSERIOCTL_H__
