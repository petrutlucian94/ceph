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
//
//	MODULE:
//
//		$File: //depot/tools/wnbdvmMEMsample/wnbdVmSampleInc/wnbdspintf.h $
//
//	ABSTRACT:
//
//      This file contains wnbdSP managment APIs.
//
//	AUTHOR:
//
//		Open Systems Resources, Inc.
// 
//	REVISION:   
//
//		$Revision: #2 $
//
///////////////////////////////////////////////////////////////////////////////
#ifndef __wnbdSPINTF_H__
#define __wnbdSPINFT_H__

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * This will create a new connection
 */
HANDLE ConnectToScsiPort();

DWORD wnbdSPConnect(const WCHAR* InstanceName,
                   USHORT       SizeMB);

/*
 * This will disconnect a connection
 */

DWORD wnbdSPDisconnect(WCHAR* InstanceName);

/*
 * This will Give a list of active connections
 */

typedef struct _ACTIVELIST_ENTRY {

    WCHAR*          InstanceName;
    USHORT          BusNumber;
    USHORT          TargetId;
    USHORT          Lun;
    USHORT          DiskSizeMB;
    USHORT          Connected;

} ACTIVELIST_ENTRY, *PACTIVELIST_ENTRY;

DWORD wnbdSPGetActiveList(PACTIVELIST_ENTRY  *PPActiveList,PULONG PCount);

#if defined(__cplusplus)
}
#endif

#endif
