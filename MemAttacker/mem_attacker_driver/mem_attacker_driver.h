// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to driver functions.

#ifndef MEM_ATTACKER_DRIVER_H_
#define MEM_ATTACKER_DRIVER_H_

#include "common.h"
#include "..\shared\mem_attacker_shared.h" // IOCTL-codes
#include "vulnerable_code.h"
#include "..\..\utils\zwfile.h"
#include "token_hijacking.h"
#include "files_hijacking.h"

#ifdef _WIN64
#define KERNEL_HANDLE_FLAG 0xFFFFFFFF80000000ULL
#else
#define KERNEL_HANDLE_FLAG 0x80000000
#endif

#define ObKernelHandleToHandle(Handle)                  \
    (HANDLE)((ULONG_PTR)(Handle) & ~KERNEL_HANDLE_FLAG)

#define ObMarkHandleAsKernelHandle(Handle)           \
    (HANDLE)((ULONG_PTR)(Handle) | KERNEL_HANDLE_FLAG)


extern "C" {

	typedef struct _EPROC_OFFSETS {
		int UniqueProcessId;
		int ActiveProcessLinks;
		int Token;
    int ObjectTable;
	}EPROC_OFFSETS, *PEPROC_OFFSETS;

	extern EPROC_OFFSETS g_EprocOffsets;

	extern PSHORT NtBuildNumber;
 	extern void* /*PHANDLE_TABLE*/ ObpKernelHandleTable; // <- does not work with ExEnumHandleTable()
 	extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;

#pragma pack (push, 1)

	typedef struct _HANDLE_TABLE
	{
		ULONG NextHandleNeedingPool;		// + 0x000 NextHandleNeedingPool : Uint4B
		long ExtraInfoPages;				// + 0x004 ExtraInfoPages : Int4B
		LONG_PTR TableCode;					// + 0x008 TableCode : Uint8B
		PEPROCESS QuotaProcess;				// + 0x010 QuotaProcess : Ptr64 _EPROCESS
		LIST_ENTRY HandleTableList;			// + 0x018 HandleTableList : _LIST_ENTRY
		ULONG UniqueProcessId;				// + 0x028 UniqueProcessId : Uint4B
		ULONG Flags;						// + 0x02c Flags : Uint4B 
		EX_PUSH_LOCK HandleContentionEvent;	// 		+ 0x02c StrictFIFO : Pos 0, 1 Bit
		EX_PUSH_LOCK HandleTableLock;		// 		+ 0x02c EnableHandleExceptions : Pos 1, 1 Bit
		// More fields here...				//		+ 0x02c Rundown : Pos 2, 1 Bit
	} HANDLE_TABLE, *PHANDLE_TABLE;			//		+ 0x02c Duplicated : Pos 3, 1 Bit
											//		+ 0x02c RaiseUMExceptionOnInvalidHandleClose : Pos 4, 1 Bit
											// + 0x030 HandleContentionEvent : _EX_PUSH_LOCK
											// + 0x038 HandleTableLock : _EX_PUSH_LOCK
											// + 0x040 FreeLists : [1] _HANDLE_TABLE_FREE_LIST
											// + 0x040 ActualEntry : [32] UChar
											// + 0x060 DebugInfo : Ptr64 _HANDLE_TRACE_DEBUG_INFO

	typedef struct _HANDLE_TABLE_ENTRY_INFO {
		ULONG AuditMask;				//+ 0x000 AuditMask        : Uint4B
		ULONG MaxRelativeAccessMask;		//+ 0x004 MaxRelativeAccessMask : Uint4B
	}HANDLE_TABLE_ENTRY_INFO, *PHANDLE_TABLE_ENTRY_INFO;

	typedef struct _EXHANDLE                                                        // 4 / 4 elements; 0x0004 / 0x0008 Bytes
	{
		union                                                                       // 3 / 3 elements; 0x0004 / 0x0008 Bytes
		{
			struct _tag                                                                 // 2 / 2 elements; 0x0004 / 0x0004 Bytes
			{
				ULONG32             TagBits : 2; // 0x0000 / 0x0000; Bits:  0 -  1
				ULONG32             Index : 30; // 0x0000 / 0x0000; Bits:  2 - 31
			}tag;
			PVOID                   GenericHandleOverlay;                           // 0x0000 / 0x0000; 0x0004 / 0x0008 Bytes
			UINT_PTR                Value;                                          // 0x0000 / 0x0000; 0x0004 / 0x0008 Bytes
		};
	} EXHANDLE, *PEXHANDLE;

	typedef struct _HANDLE_TABLE_ENTRY // Size=16
	{
		union
		{
			ULONG_PTR VolatileLowValue; // Size=8 Offset=0
			ULONG_PTR LowValue; // Size=8 Offset=0
			HANDLE_TABLE_ENTRY_INFO * InfoTable; // Size=8 Offset=0
			ULONG_PTR RefCountField;
			struct _tag1
			{
				ULONG_PTR Unlocked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
				ULONG_PTR RefCnt : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
				ULONG_PTR Attributes : 3; // Size=8 Offset=0 BitOffset=17 BitCount=3
				ULONG_PTR ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
			}tag1;
		};
		union
		{
			ULONG_PTR HighValue; // Size=8 Offset=8
			_HANDLE_TABLE_ENTRY * NextFreeHandleEntry; // Size=8 Offset=8
			EXHANDLE LeafHandleValue; // Size=8 Offset=8
			struct _tag2
			{
				ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
				ULONG NoRightsUpgrade : 1; // Size=4 Offset=8 BitOffset=25 BitCount=1
				ULONG Spare1 : 6; // Size=4 Offset=8 BitOffset=26 BitCount=6
			}tag2;
			ULONG Spare2; // Size=4 Offset=12
		};
	} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
	
#pragma pack(pop)

// _HANDLE_TABLE_ENTRY
//
// [ X ] [ X ] [ 0 ] [ 1 ] [ 2 ] [ 3 ] [ 4 ] [ 5 ] [ 6 ]
//   |     |     |     |     |     |     |     |     |
//   |     |      \-----\-----\-----\-----\-----\-----\-----> (63:20) ObjectPointerBits
//   |     |     |
//   |     |      \-----------------------------------------> (19:17)] Attributes
//   |     |
//   |\-----\-----------------------------------------------> (16: 1)] RefCnt
//   |
//    \----------------------------------------------------->[(0: 0)] Unlocked
// 
// Here are the details of ObjectPointerBits:
//

#define OBJECTPOINTERBITS_SIZE		6	/* <-  ~six bytes (63:20) - 44 bits  */
#define OBJECTPOINTERBITS_OFFSET	2	/* <-  two bytes from the begging of the PHANDLE_TABLE_ENTRY  */
#define HANDLE_TABLE_ENTRY_SZ		sizeof(HANDLE_TABLE_ENTRY)




#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)

#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )

	typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
		IN PHANDLE_TABLE HandleTable,
		IN PHANDLE_TABLE_ENTRY HandleTableEntry,
		IN HANDLE Handle,
		IN PVOID EnumParameter
		);

	NTKERNELAPI
		BOOLEAN
		ExEnumHandleTable(
			IN PHANDLE_TABLE HandleTable,
			IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
			IN PVOID EnumParameter,
			OUT PHANDLE Handle
		);

// 	NTKERNELAPI
// 		VOID
// 		ExUnlockHandleTableEntry(
// 			__inout PHANDLE_TABLE HandleTable,
// 			__inout PHANDLE_TABLE_ENTRY HandleTableEntry
// 		);

	// 	NTKERNELAPI PHANDLE_TABLE_ENTRY
	// 		ExMapHandleToPointer(
	// 			IN  PHANDLE_TABLE HandleTable,
	// 			IN  HANDLE Handle
	// 		);


	NTKERNELAPI
		VOID
		FASTCALL
		ExfUnblockPushLock(
			IN OUT PEX_PUSH_LOCK PushLock,
			IN OUT PVOID WaitBlock
		);

NTKERNELAPI UCHAR *NTAPI PsGetProcessImageFileName(_In_ PEPROCESS process);

#define MEM_ATTACKER_LOGGER(format, ...) \
  DbgPrint("[%ws] ", MEM_ATTACKER_NAME); \
  DbgPrint((format), __VA_ARGS__); \
	DbgPrint("\r\n");
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

#endif  // MEM_ATTACKER_DRIVER_H_
