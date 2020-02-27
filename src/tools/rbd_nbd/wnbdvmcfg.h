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
//		$File: //depot/tools/wnbdvmMEMsample/wnbdVmSampleInc/wnbdVmCfg.h $
//
//	ABSTRACT:
//
//      This file contains Configuration information used by the application
//		and the driver.
//
//	AUTHOR:
//
//		Open Systems Resources, Inc.
// 
//	REVISION:   
//
//		$Revision: #3 $
//
///////////////////////////////////////////////////////////////////////////////
#ifndef __WNBDVMCFG_H__
#define __WNBDVMCFG_H__

#if defined(__cplusplus)
extern "C" {
#endif

#define FILE_DEVICE_WNBDVMPORT   63273

#define WNBDVM_VM_IOCTL_START 3079
#define USER_VM_IOCTL_START 3085

typedef struct _COMMAND_IN {
	ULONG		IoControlCode;
} COMMAND_IN, *PCOMMAND_IN;

// {2B64D37A-FDD5-4e10-9EBB-834206ED9009}
static const GUID GUID_WNBD_VIRTUALMINIPORT = 
{ 0x2b64d37a, 0xfdd5, 0x4e10, { 0x9e, 0xbb, 0x83, 0x42, 0x6, 0xed, 0x90, 0x9 } };

#if defined(__cplusplus)
}
#endif

#endif __WNBDVMCFG_H__
