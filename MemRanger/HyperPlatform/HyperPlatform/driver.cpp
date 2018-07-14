// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif
#include "driver.h"


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

static DRIVER_DISPATCH DriverpCreateClose;
static DRIVER_DISPATCH DriverpReadWrite;
static DRIVER_DISPATCH DriverpDeviceControl;

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS create_device(IN PDRIVER_OBJECT pDrv, ULONG uFlags, PWCHAR devName, PWCHAR linkName);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)

#pragma alloc_text(PAGE, DriverpCreateClose)
#pragma alloc_text(PAGE, DriverpReadWrite)
#pragma alloc_text(PAGE, DriverpDeviceControl)
#pragma alloc_text(PAGE, create_device)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// A driver entry point
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                            PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();

  static const wchar_t kLogFilePath[] = L"\\SystemRoot\\MemoryMonRWE.log";
  static const auto kLogLevel =
      (IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName
                         : kLogPutLevelDebug | kLogOptDisableFunctionName;

  auto status = STATUS_UNSUCCESSFUL;
  driver_object->DriverUnload = DriverpDriverUnload;
  driver_object->MajorFunction[IRP_MJ_CREATE] =
  driver_object->MajorFunction[IRP_MJ_CLOSE] = DriverpCreateClose;
  driver_object->MajorFunction[IRP_MJ_READ] =
  driver_object->MajorFunction[IRP_MJ_WRITE] = DriverpReadWrite;
  driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverpDeviceControl;
  status = create_device(driver_object, NULL, ALLMEMPRO_DEVICENAME_DRV, ALLMEMPRO_LINKNAME_DRV);

  HYPERPLATFORM_COMMON_DBG_BREAK();

  // Request NX Non-Paged Pool when available
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

  // Initialize log functions
  bool need_reinitialization = false;
  status = LogInitialization(kLogLevel, kLogFilePath);
  if (status == STATUS_REINITIALIZATION_NEEDED) {
    need_reinitialization = true;
  } else if (!NT_SUCCESS(status)) {
    return status;
  }

  if (!NT_SUCCESS(init_global_vars())) {
	  return STATUS_CANCELLED;
  }

  // Test if the system is supported
//   if (!DriverpIsSuppoetedOS()) {
//     LogTermination();
//     return STATUS_CANCELLED;
//   }

  // Initialize global variables
  status = GlobalObjectInitialization();
  if (!NT_SUCCESS(status)) {
    LogTermination();
    return status;
  }

  // Initialize perf functions
  status = PerfInitialization();
  if (!NT_SUCCESS(status)) {
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize utility functions
  status = UtilInitialization(driver_object);
  if (!NT_SUCCESS(status)) {
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize power callback
  status = PowerCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize hot-plug callback
  status = HotplugCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Virtualize all processors
  status = VmInitialization();
  if (!NT_SUCCESS(status)) {
	  HotplugCallbackTermination();
	  PowerCallbackTermination();
	  UtilTermination();
	  PerfTermination();
	  GlobalObjectTermination();
	  LogTermination();
	  return status;
  }

  status = TestInitialization();
  if (!NT_SUCCESS(status)) {
	  VmTermination();
	  HotplugCallbackTermination();
	  PowerCallbackTermination();
	  UtilTermination();
	  PerfTermination();
	  GlobalObjectTermination();
	  LogTermination();
	  return status;
  }

  // Register re-initialization for the log functions if needed
  if (need_reinitialization) {
	  LogRegisterReinitialization(driver_object);
  }

  HYPERPLATFORM_LOG_INFO("The VMM has been installed.");
  TestRwe();

  return status;
}

// Unload handler
_Use_decl_annotations_ static void DriverpDriverUnload(
    PDRIVER_OBJECT driver_object) {
  UNREFERENCED_PARAMETER(driver_object);
  PAGED_CODE();

  HYPERPLATFORM_COMMON_DBG_BREAK();

  TestTermination();
  VmTermination();
  HotplugCallbackTermination();
  PowerCallbackTermination();
  UtilTermination();
  PerfTermination();
  GlobalObjectTermination();
  LogTermination();
}

EPROC_OFFSETS g_EprocOffsets;

NTSTATUS init_global_vars() {
	g_EprocOffsets = { 0 };
	NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

	switch (*NtBuildNumber) {
	case 16299: /*   */
				/* BUILDOSVER_STR:  10.0.16299.15.amd64fre.rs3_release.170928-1534 */
		g_EprocOffsets.UniqueProcessId = 0x2e0;
		g_EprocOffsets.ActiveProcessLinks = 0x2e8;
		g_EprocOffsets.ActiveProcessLinksSize = 0x10;  // ActiveProcessLinks _LIST_ENTRY
		g_EprocOffsets.Token = 0x358;
		g_EprocOffsets.TokenSize = 0x8;// Token            : _EX_FAST_REF
		nt_status = STATUS_SUCCESS;
		break;

	case 15063: /*   */
				/* BUILDOSVER_STR:  10.0.15063.0.amd64fre.rs2_release.170317-1834 */
		g_EprocOffsets.UniqueProcessId = 0x2e0;
		g_EprocOffsets.ActiveProcessLinks = 0x2e8;
		g_EprocOffsets.ActiveProcessLinksSize = 0x10;  // ActiveProcessLinks _LIST_ENTRY
		g_EprocOffsets.Token = 0x358;
		g_EprocOffsets.TokenSize = 0x8;// Token            : _EX_FAST_REF
		nt_status = STATUS_SUCCESS;
		break;

	case 14393: /* Win10_1607_SingleLang_English_x64 */
				/* BUILDOSVER_STR:  10.0.14393.0.amd64fre.rs1_release.160715-1616 */
		g_EprocOffsets.UniqueProcessId = 0x2e8;
		g_EprocOffsets.ActiveProcessLinks = 0x2f0;
		g_EprocOffsets.ActiveProcessLinksSize = 0x10;  // ActiveProcessLinks _LIST_ENTRY
		g_EprocOffsets.Token = 0x358;
		g_EprocOffsets.TokenSize = 0x8;// Token            : _EX_FAST_REF
		nt_status = STATUS_SUCCESS;
		break;
	default:
		nt_status = STATUS_UNSUCCESSFUL;
		break;
	};
	return nt_status;
}

// Test if the system is one of supported OS versions
_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
  PAGED_CODE();

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return false;
  }
  if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
    return false;
  }
  // 4-gigabyte tuning (4GT) should not be enabled
  if (!IsX64() &&
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
    return false;
  }
  return true;
}

_Use_decl_annotations_ NTSTATUS create_device(IN PDRIVER_OBJECT pDrv, ULONG uFlags, PWCHAR devName, PWCHAR linkName) {
	UNICODE_STRING dev_name = { 0 }, link_name = { 0 };
	RtlInitUnicodeString(&dev_name, devName);
	RtlInitUnicodeString(&link_name, linkName);

	PDEVICE_OBJECT pDev;
	auto status = IoCreateDevice(pDrv, 0 /* or sizeof(DEVICE_EXTENSION)*/, &dev_name, 65500, 0, 0, &pDev);

	if (NT_SUCCESS(status)) {
		pDev->Flags |= uFlags;
		IoDeleteSymbolicLink(&link_name);
		status = IoCreateSymbolicLink(&link_name, &dev_name);
	}
	else { IoDeleteDevice(pDev); }

	return status;
}


// Create-Close handler
_Use_decl_annotations_ static NTSTATUS DriverpCreateClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP  Irp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	PAGED_CODE();

	const auto stack = IoGetCurrentIrpStackLocation(Irp);
	switch (stack->MajorFunction) {
		case IRP_MJ_CREATE: 
			break;
		case IRP_MJ_CLOSE: 
			break;
	}
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, 0);
	return STATUS_SUCCESS;
}


// Read Write handler
_Use_decl_annotations_ static NTSTATUS DriverpReadWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP  Irp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	PAGED_CODE();

	PVOID buf = NULL;
	auto buf_size = 0;
	// Read size of input buffer 
	const auto stack = IoGetCurrentIrpStackLocation(Irp);
	switch (stack->MajorFunction) {
		case IRP_MJ_READ: 
			buf_size = stack->Parameters.Read.Length; 
			break;
		case IRP_MJ_WRITE: 
			buf_size = stack->Parameters.Write.Length; 
			break;
	}
	// Get the address of input buffer
	if (buf_size) {
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
	OUT PVOID &outBuf, OUT ULONG &outBufSize) {
	UNREFERENCED_PARAMETER(pIrp);
	PAGED_CODE();

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

_Use_decl_annotations_ static NTSTATUS DriverpDeviceControl(
	IN PDEVICE_OBJECT pDeviceObject, 
	IN PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);
	PAGED_CODE();

	const auto stack = IoGetCurrentIrpStackLocation(pIrp);
	PVOID in_buf = NULL, out_buf = NULL;
	ULONG in_buf_sz = 0, out_buf_sz = 0;
	auto status = STATUS_INVALID_PARAMETER;
	ULONG_PTR info = 0;
	read_param(pIrp, in_buf, in_buf_sz, out_buf, out_buf_sz);
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case ALLMEMPRO_ADD_MEMORY_ACCESS_RULE:
		if ((in_buf_sz == sizeof MEMORY_ACCESS_RULE) && in_buf) {
			MEMORY_ACCESS_RULE mem_rule = { 0 };
			RtlCopyMemory(&mem_rule, in_buf, sizeof MEMORY_ACCESS_RULE);
			RweAddMemoryAccessRule(mem_rule);
			RweAddAllocRange(mem_rule.allocStartAddr, mem_rule.allocSize);
			RweApplyRanges();
		}
		break;
	case ALLMEMPRO_GET_MEMORY_ACCESS_RULES:
		status = RweGetMemoryAccessRules((MEMORY_ACCESS_RULE *)in_buf, in_buf_sz);
		info = in_buf_sz;
		break;
	case ALLMEMPRO_SET_TSC_DELTA:
		if ((in_buf_sz == sizeof ULONG64) && in_buf) {
			ULONG64 delta = 0;
			__try {
				delta = *((ULONG64 *)in_buf);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				delta = 0;
			}
			if (delta) {
				set_delta_to_cheat_tsc(delta);
			}
			break;
		}
	default: {}
	}

	pIrp->IoStatus.Information = info;
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

}  // extern "C"
