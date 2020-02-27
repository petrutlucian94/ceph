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
//		$File: //depot/tools/wnbdvmMEMsample/wnbdVmSampleInc/wnbdVmdebug.h $
//
//	ABSTRACT:
//
//      This file contains Debug information
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
#ifndef TRACE_LEVEL_INFORMATION

#if defined(__cplusplus)
extern "C" {
#endif

#define TRACE_LEVEL_NONE        0   // Tracing is not on
#define TRACE_LEVEL_FATAL       1   // Abnormal exit or termination
#define TRACE_LEVEL_ERROR       2   // Severe errors that need logging
#define TRACE_LEVEL_WARNING     3   // Warnings such as allocation failure
#define TRACE_LEVEL_INFORMATION 4   // Includes non-error cases(e.g.,Entry-Exit)
#define TRACE_LEVEL_VERBOSE     5   // Detailed traces from intermediate steps
#define TRACE_LEVEL_RESERVED6   6
#define TRACE_LEVEL_RESERVED7   7
#define TRACE_LEVEL_RESERVED8   8
#define TRACE_LEVEL_RESERVED9   9
#endif // TRACE_LEVEL_INFORMATION


#define WNBDVMINIPT_DEBUG_ERROR                   0x00000001
#define WNBDVMINIPT_DEBUG_FUNCTRACE               0x00000002
#define WNBDVMINIPT_DEBUG_PNP_INFO                0x00000004
#define WNBDVMINIPT_DEBUG_IOCTL_INFO              0x00000008
#define WNBDVMINIPT_DEBUG_POWER_INFO              0x00000010
#define WNBDVMINIPT_DEBUG_WMI_INFO                0x00000020
#define WNBDVMINIPT_DEBUG_SRB                     0x00000040
#define WNBDVMINIPT_DEBUG_USER                    0x00000080
#define WNBDVMINIPT_DEBUG_USER_READ               0x00000100
#define WNBDVMINIPT_DEBUG_USER_WRITE              0x00000200
#define WNBDVMINIPT_DEBUG_CLUSTER                 0x00000400
#define WNBDVMINIPT_DEBUG_SRB_STATUS              0x00000800
#define WNBDVMINIPT_DEBUG_ADAPTER                 0x00001000
#define WNBDVMINIPT_DEBUG_SHUTDOWN_FLUSH          0x00002000
#define WNBDVMINIPT_DEBUG_SUMMARY                 0x00004000
#define WNBDVMINIPT_DEBUG_DRIVER_ENTRY            0x00008000
#define WNBDVMINIPT_DEBUG_USER_CONNECTION         0x00010000
#define WNBDVMINIPT_DEBUG_SRB_USER                0x00020000
#define WNBDVMINIPT_DEBUG_SERVICE                 0x00040000
#define WNBDVMINIPT_DEBUG_ALL                     0xFFFFFFFF

extern ULONG wnbdTraceLevel;
extern ULONG wnbdDbgFlags;

//
// Define these as a way to get around the linker warnings seen
// for duplicates of KeInitializeSpinLock.   We don't like having to
// do this, but we don't like warnings either.
//
VOID wnbdInitializeSpinLock(PKSPIN_LOCK a);
VOID wnbdAcquireSpinLock(PKSPIN_LOCK a,KIRQL* b); 
VOID wnbdReleaseSpinLock(PKSPIN_LOCK a,KIRQL b) ;



#if DBG

#define wnbdTracePrint(Level,Flags,X) \
{ \
    if(Level <= wnbdTraceLevel && Flags & wnbdDbgFlags) { \
        DbgPrint X; \
    } \
}

#else // DBG

#define wnbdTracePrint(Level,Flags,X)

#endif // DBG

#if DBG

#define wnbdBreakPoint() \
do { \
      __try { \
              DbgPrint("BreakPoint %s %d\n",__FILE__,__LINE__); \
              DbgBreakPoint(); \
      } __except(_exception_code() == STATUS_BREAKPOINT ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH) { (0); }  \
} while (0)

#define wnbdASSERT(exp) \
do { \
    _try{ \
        if (!(exp)) {\
            DbgPrint("ASSERTION FAILED: %s (file %s, line %d) %s\n", #exp, __FILE__, __LINE__, "" ); \
            DbgBreakPoint(); \
        } \
    } _except(EXCEPTION_EXECUTE_HANDLER) {         \
        KeBugCheckEx(0x00010001,0,0,0,0); \
    }                       \
} while (0)

#else //DBG>0

#define wnbdBreakPoint()

#define wnbdASSERT(x) \
    { \
        if(!(x)) {\
            KeBugCheckEx(0x00010001,0,0,0,0); \
        } \
    }

#if defined(__cplusplus)
}
#endif

#endif //DBG>0
