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
//    MODULE:
//
//        $File: //depot/tools/wnbdvmMEMsample/wnbdVmSampleInc/wnbdVmUserIntf.h $
//
//    ABSTRACT:
//
//      This contains the wnbd Virtual Miniport Driver inteface functions
//		that let the wnbd Virtual miniport framework communicate with the
//		user layer that implements the scsi devices to export...
//
//    AUTHOR:
//
//        wnbd Open Systems Resources, Inc.
// 
//    REVISION:   
//
//        $Revision: #2 $
//
///////////////////////////////////////////////////////////////////////////////
#ifndef __WNBDVMUSERINTF_H__
#define __WNBDVMUSERINTF_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <scsiwmi.h>
#ifdef __cplusplus
	extern "C" {
#endif


extern UNICODE_STRING wnbdRegistryPath;

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS wnbdUserProcessIoCtl(IN PVOID PUserGlobalHandle,IN  PIRP Irp);
VOID     wnbdUserGetScsiCapabilities(IN PVOID PUserGlobalHandle,
									PIO_SCSI_CAPABILITIES PCapabilities);
NTSTATUS wnbdUserInitialize(PVOID wnbdSpHandle,PDEVICE_OBJECT Pdo,
						   PVOID* UserGlobalInfoHandle,PULONG PNodeNumber);
NTSTATUS wnbdUserAdapterStarted(IN PVOID PUserGlobalHandle);
VOID     wnbdUserDeleteGlobalInformation(PVOID PUserGlobalInfo);
VOID     wnbdUserShutdownNotification(PVOID PUserGlobalInfo);
NTSTATUS wnbdUserRescanBus(IN PVOID PUserGlobalHandle);
NTSTATUS wnbdUserResetBus(IN PVOID PUserGlobalHandle);
NTSTATUS wnbdUserHandleSrb(IN PVOID PDevExt, IN PVOID UserLocalInfoHandle,PSCSI_REQUEST_BLOCK PSrb);
ULONG	 wnbdUserGetSrbExtensionSize(VOID);
VOID     wnbdUserDeleteLocalInformation(IN PVOID UserLocalInfoHandle);
VOID     wnbdUserLocalShutdownNotification(PVOID UserLocalInfo);
VOID	 BlaDiskThread(IN PVOID            Context);




PVOID   wnbdSPCreateScsiDevice(IN PVOID PwnbdGHandle,IN ULONG BusIndex,
                              IN ULONG TargetIndex,IN ULONG LunIndex,
                              IN PVOID UserLocalHandle,
                              IN BOOLEAN BReadOnlyDevice,
                              PINQUIRYDATA PInquiryData,
                              ULONG ExtraStackLocations);

void    wnbdSPAnnounceArrival(IN PVOID PwnbdGHandle);
void    wnbdSPAnnounceDeparture(IN PVOID PwnbdGHandle);
BOOLEAN wnbdSPSetDeviceRemovable(IN PVOID PwnbdLHandle,BOOLEAN BForce);
BOOLEAN wnbdSPCanUserStart(IN PVOID PwnbdGHandle);
PDRIVER_OBJECT wnbdSPGetDriverObject(IN PVOID PwnbdGHandle);
PDEVICE_OBJECT wnbdSpGetDeviceObject(IN PVOID PwnbdLHandle);
PVOID	wnbdSpGetSrbDataAddress(IN PVOID PwnbdLHandle,PSCSI_REQUEST_BLOCK PSrb);
PMDL	wnbdSpGetSrbMdl(IN PVOID PwnbdLHandle,PSCSI_REQUEST_BLOCK PSrb);
void	wnbdSPDecOutstandingIoCount(IN PVOID PwnbdLHandle);
void    wnbdSpCompleteSrb(IN PVOID PwnbdLHandle,PSCSI_REQUEST_BLOCK PSrb);


PUCHAR	wnbdSpPrintSCSICDBOperation(UCHAR Operation);
void	wnbdSpPrintCdb10(PCDB PCdb);
VOID	wnbdSpPrintCdb12(PCDB PCdb);
VOID	wnbdSpPrintModeSense(UCHAR Type,PCDB PCdb);
PUCHAR	wnbdSpPrintSRBStatus(USHORT Status);
PUCHAR	wnbdSpPrintSCSStatus(USHORT Status);
VOID	wnbdSpPrintScsiInquiryData(UCHAR Bus,UCHAR Target,UCHAR Lun,PINQUIRYDATA PInquiryData);

#ifdef __cplusplus
};
#endif

typedef struct _HW_SRB_EXTENSION_VM {
	SCSIWMI_REQUEST_CONTEXT WmiRequestContext;
} HW_SRB_EXTENSION_VM, *PHW_SRB_EXTENSION_VM;

typedef struct _HW_SRB_EXTENSION {
	//
	// Used to queue the SRB to a worker thread for execution.
	//
	HW_SRB_EXTENSION_VM		VMExtension;

	//
	// Start of User VM data;
	//
    UCHAR					UserData[1];
} HW_SRB_EXTENSION, *PHW_SRB_EXTENSION;

#endif  __WNBDVMUSERINTF_H__