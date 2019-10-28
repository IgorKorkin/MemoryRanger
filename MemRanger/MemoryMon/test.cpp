// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements RWE functions.

#include "test.h"
#include <intrin.h>
#include "../HyperPlatform/common.h"
#include "../HyperPlatform/log.h"
#include "../HyperPlatform/util.h"
#include "rwe.h"
#include "test_util.h"
#include "mem_trace.h"
#include "../HyperPlatform/driver.h" // < 

#pragma warning(disable : 4505)

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

struct RTL_PROCESS_MODULE_INFORMATION {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) static void TestpRwe1(
    _Inout_ UCHAR* pagable_test_page);

_IRQL_requires_max_(PASSIVE_LEVEL) static void TestpRwe2();

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS TestpForEachDriver(
    _In_ bool (*callback)(const RTL_PROCESS_MODULE_INFORMATION&, void*),
    _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool TestpForEachDriverCallback(
    _In_ const RTL_PROCESS_MODULE_INFORMATION& module, _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) static void TestpLoadImageNotifyRoutine(
    _In_opt_ PUNICODE_STRING full_image_name, _In_ HANDLE process_id,
    _In_ PIMAGE_INFO image_info);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool TestpIsThisProcessLaunchedByExplorer(HANDLE ProcessId);

_IRQL_requires_max_(PASSIVE_LEVEL) static void TextpAddNewProcessToken(_In_ HANDLE ProcessId, PEPROCESS Process);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool TextpDelEprocessStructs(_In_ HANDLE ProcessId);

_IRQL_requires_max_(PASSIVE_LEVEL) static void TestpCreateProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, TestInitialization)
#pragma alloc_text(INIT, TestRwe)
#pragma alloc_text(INIT, TestpForEachDriver)
#pragma alloc_text(INIT, TestpForEachDriverCallback)
#pragma alloc_text(PAGE, TestTermination)

#pragma alloc_text(PAGE, TestpAddOSInternalDrivers)
#pragma alloc_text(PAGE, TestpLoadImageNotifyRoutine)

#pragma alloc_text(PAGE, TestpIsThisProcessLaunchedByExplorer)
#pragma alloc_text(PAGE, TextpAddNewProcessToken)
#pragma alloc_text(PAGE, TextpDelEprocessStructs)
#pragma alloc_text(PAGE, TestpCreateProcessNotifyRoutineEx)



// Locate TestpRwe1 on a NonPagable code section outside of the .text section
// and TestpRwe2 on Pagable code section outside of the PAGE section. Note that
// MSVC seems to make a section pagable when a section name starts with PAGE and
// any other code sections are set as NonPagable as default.
#pragma alloc_text(textTEST, TestpRwe1)
#pragma alloc_text(PAGETEST, TestpRwe2)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

_Use_decl_annotations_ NTSTATUS TestInitialization() {
  PAGED_CODE();

  auto status = PsSetLoadImageNotifyRoutine(TestpLoadImageNotifyRoutine);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = PsSetCreateProcessNotifyRoutineEx(TestpCreateProcessNotifyRoutineEx, FALSE);
  if (!NT_SUCCESS(status)) {
    return status;
  }


  return status;
}
_Use_decl_annotations_ void TestTermination() {
  PAGED_CODE();

  PsSetCreateProcessNotifyRoutineEx(TestpCreateProcessNotifyRoutineEx, TRUE);
  PsRemoveLoadImageNotifyRoutine(TestpLoadImageNotifyRoutine);
}

// Runs a set of tests for MemoryMonRWE
_Use_decl_annotations_ void TestRwe() {
  PAGED_CODE();

  //HYPERPLATFORM_COMMON_DBG_BREAK();

  if (MemTraceIsEnabled()) {
    TestpForEachDriver(TestpForEachDriverCallback, nullptr);
    RweApplyRanges();
    HYPERPLATFORM_COMMON_DBG_BREAK();
    HYPERPLATFORM_LOG_INFO("Enabled.");
    return;
  }

  // Initialize a fake page filled with zero for read protect
  g_rwe_zero_page = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE,
                                          kHyperPlatformCommonPoolTag);
  if (!g_rwe_zero_page) {
    return;
  }
  RtlZeroMemory(g_rwe_zero_page, PAGE_SIZE);

  // Protect HalDispatchTable[1] from being written
  HYPERPLATFORM_LOG_INFO("Write Protect: %p : hal!HalDispatchTable[1]",
                         &HalQuerySystemInformation);
  RweAddDstRange(&HalQuerySystemInformation, sizeof(void*));

  // Protect PoolBigPageTableSize from being read
  HYPERPLATFORM_LOG_INFO("Read  Protect: %p : nt!PoolBigPageTableSize",
                         kRwePoolBigPageTableSizeAddress);
  RweAddDstRange(kRwePoolBigPageTableSizeAddress, sizeof(void*));

  // Protect PsInitialSystemProcess from being read
  HYPERPLATFORM_LOG_INFO("Read  Protect: %p : nt!PsInitialSystemProcess 0x%I64X",
    PsInitialSystemProcess, *(PULONG64)PsInitialSystemProcess );
  RweAddDstRange(PsInitialSystemProcess, sizeof(void*));

  RweApplyRanges();

#if 0

  // Set TestpRwe1() and TestpRwe2() as source ranges. Those functions are
  // located at the page boundaries: xxxxTEST and PAGETEST sections
  // respectively.
  //
  // It is safe to set an entire pages as source ranges as those sections do not
  // contain any other contents.
  RweAddSrcRange(&TestpRwe1, PAGE_SIZE);
  RweAddSrcRange(&TestpRwe2, PAGE_SIZE);

  // Set DbgPrintEx() and KdDebuggerNotPresent as dest ranges so that access to
  // those from TestpRwe1() and TestpRwe2() can be monitored. It is not fully
  // analyzed and tested what happens if outside of those ranges but still
  // inside the page is accessed.
  RweAddDstRange(&DbgPrintEx, 1);
  RweAddDstRange(KdDebuggerNotPresent, 1);

  // Set a pageable test page as a dest range. Touch it so that the VA is backed
  // by PA for testing purpose.
  const auto pagable_test_page = reinterpret_cast<UCHAR*>(
      ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, kHyperPlatformCommonPoolTag));
  if (!pagable_test_page) {
    return;
  }
  RtlZeroMemory(pagable_test_page, PAGE_SIZE);
  RweAddDstRange(pagable_test_page, PAGE_SIZE);

  // Reflect all range data to EPT
  RweApplyRanges();

  // Run the first test. All of source and dest ranges will be backed by PA now.
  HYPERPLATFORM_COMMON_DBG_BREAK();
  TestpRwe1(pagable_test_page);
  TestpRwe2();
  HYPERPLATFORM_LOG_DEBUG("pagable_test_page[0]: %02x", *pagable_test_page);

  // Forcibly page out memory as much as possible.
  NT_VERIFY(NT_SUCCESS(TestUtilPageOut()));

  // Run the second test. Some of ranges will not be backed by PA until they
  // are accessed by test code.
  HYPERPLATFORM_COMMON_DBG_BREAK();
  TestpRwe1(pagable_test_page);
  TestpRwe2();
  HYPERPLATFORM_LOG_DEBUG("pagable_test_page[0]: %02x", *pagable_test_page);

  // Test finished
  HYPERPLATFORM_COMMON_DBG_BREAK();
  ExFreePoolWithTag(pagable_test_page, kHyperPlatformCommonPoolTag);
#endif
}

// A test function located in a non-pagable page
_Use_decl_annotations_ static void TestpRwe1(UCHAR* pagable_test_page) {
  const auto not_present = *KdDebuggerNotPresent;

  // Read inside one of dest ranges
  if (!not_present) {
    // Execute inside one of dest ranges. It is likely that not_present is now
    // stored in a register and access to it is not reported here.
    HYPERPLATFORM_LOG_INFO("Hello from %s (*KdDebuggerNotPresent = %d)",
                           __FUNCTION__, not_present);
  }

  // Write inside one of dest ranges
  *KdDebuggerNotPresent = 0xff;
  *KdDebuggerNotPresent = not_present;

// Read from and write to the pagable test page. This address may or may not
// be backed by PA before this write operation.
#if defined(_AMD64_)
  const auto current_value = *reinterpret_cast<ULONG64*>(pagable_test_page);
  __stosq(reinterpret_cast<ULONG64*>(pagable_test_page),
          current_value + 0x1111111111111111, PAGE_SIZE / sizeof(ULONG64));
#else
  const auto current_value = *reinterpret_cast<ULONG*>(pagable_test_page);
  __stosd(reinterpret_cast<ULONG*>(pagable_test_page),
          current_value + 0x11111111, PAGE_SIZE / sizeof(ULONG));
#endif
}

// A test function located in a pageable page
_Use_decl_annotations_ static void TestpRwe2() {
  PAGED_CODE();

  // Execute inside one of dest ranges
  HYPERPLATFORM_LOG_INFO("Hello from %s", __FUNCTION__);
}

// Executes callback for each driver currently loaded
_Use_decl_annotations_ static NTSTATUS TestpForEachDriver(
    bool (*callback)(const RTL_PROCESS_MODULE_INFORMATION&, void*),
    void* context) {
  PAGED_CODE();

  // For ZwQuerySystemInformation
  enum SystemInformationClass {
    SystemModuleInformation = 11,
  };

  NTSTATUS NTAPI ZwQuerySystemInformation(
      _In_ SystemInformationClass SystemInformationClass,
      _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength,
      _Out_opt_ PULONG ReturnLength);

  struct RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
  };

  // Get a necessary size of buffer
  ULONG_PTR dummy = 0;
  ULONG return_length = 0;
  auto status = ZwQuerySystemInformation(SystemModuleInformation, &dummy,
                                         sizeof(dummy), &return_length);
  if (NT_SUCCESS(status) || return_length <= sizeof(dummy)) {
    return status;
  }

  // Allocate s bit larger buffer to handle new processes in case
  const ULONG allocation_size =
      return_length + sizeof(RTL_PROCESS_MODULE_INFORMATION) * 3;
  const auto system_info =
      reinterpret_cast<RTL_PROCESS_MODULES*>(ExAllocatePoolWithTag(
          PagedPool, allocation_size, kHyperPlatformCommonPoolTag));
  if (!system_info) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }

  status = ZwQuerySystemInformation(SystemModuleInformation, system_info,
                                    allocation_size, &return_length);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(system_info, kHyperPlatformCommonPoolTag);
    return status;
  }

  // For each process
  for (auto i = 0ul; i < system_info->NumberOfModules; ++i) {
    const auto& module = system_info->Modules[i];
    if (!callback(module, context)) {
      break;
    }
  }

  ExFreePoolWithTag(system_info, kHyperPlatformCommonPoolTag);
  return status;
}

// Sets certain drivers as source ranges
_Use_decl_annotations_ static bool TestpForEachDriverCallback(
    const RTL_PROCESS_MODULE_INFORMATION& module, void* context) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(context);

  HYPERPLATFORM_LOG_DEBUG(
      "%p - %p: %s", module.ImageBase,
      reinterpret_cast<ULONG_PTR>(module.ImageBase) + module.ImageSize,
      module.FullPathName);

  const auto name = reinterpret_cast<const char*>(module.FullPathName) +
                    module.OffsetToFileName;
  if (MemTraceIsTargetSrcAddress(name)) {
    RweAddSrcRange(module.ImageBase, module.ImageSize);
  }
  return true;
}

void TestpAddOSInternalDrivers() {
  static UNICODE_STRING os_drivers[] = {
    RTL_CONSTANT_STRING(L"*\\NTOSKRNL.EXE"),
    RTL_CONSTANT_STRING(L"*\\NTKRNLPA.EXE"),
    RTL_CONSTANT_STRING(L"*\\NTKRNLMP.EXE"),
    RTL_CONSTANT_STRING(L"*\\NTKRNLAMP.EXE"),

    // For memory allocation:
    RTL_CONSTANT_STRING(L"*\\WDFLDR.SYS"),
    RTL_CONSTANT_STRING(L"*\\WDF01000.SYS"),  //  Wdf01000!LibraryRegisterClient
    RTL_CONSTANT_STRING(L"*\\BAM.SYS"), // Background Activity Moderator Driver (bam) for EPROCESS

                                        // For read\write operations with FILE_OBJECT
                                        RTL_CONSTANT_STRING(L"*\\FLTMGR.SYS"),	//  Microsoft Filesystem Filter Manager
                                        RTL_CONSTANT_STRING(L"*\\WCIFS.SYS"),	//  Windows Container Isolation (wcifs) Service, wcifs!WcPreWrite
                                        RTL_CONSTANT_STRING(L"*\\LUAFV.SYS"),	//  LUA File Virtualization Filter Driver or UAC File Virtualization, luafv!LuafvPreWrite
                                        RTL_CONSTANT_STRING(L"*\\WOF.SYS"),		//  Windows Overlay Filter, Wof!WofAcquireFileSystemRundown
                                        RTL_CONSTANT_STRING(L"*\\NTFS.SYS"),	//  New Technology File System , NTFS!NtfsFsdWrite

                                        RTL_CONSTANT_STRING(L"*\\MEMORYRANGER.SYS")
  };

  for (auto& driver : os_drivers) {
    PVOID drv_base = 0;
    ULONG drv_size = 0;
    if (UtilpGetAnyModuleHeaderInfo(driver, &drv_base, drv_size)) {
      HYPERPLATFORM_LOG_INFO("OS driver \"%wZ\" has been added.", driver);
      RweAddOneOSInternalDriverRange(drv_base, drv_size);
    }
  }
}

_Use_decl_annotations_ static void TestpLoadImageNotifyRoutine(
    PUNICODE_STRING full_image_name,
    HANDLE process_id,  // pid into which image is being mapped
    PIMAGE_INFO image_info) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(process_id);

  if (!full_image_name || !image_info->SystemModeImage) {
    return;
  }

  HYPERPLATFORM_LOG_DEBUG("New driver: %wZ", full_image_name);

  static UNICODE_STRING kTargetDriverExpressions[] = {
      RTL_CONSTANT_STRING(L"*\\MEMALLOCATOR*.SYS"),
      RTL_CONSTANT_STRING(L"*\\MEMATTACKER*.SYS"),

      RTL_CONSTANT_STRING(L"*\\NOIMAGE.SYS"),
      RTL_CONSTANT_STRING(L"*\\UNLINKED.SYS"),
      RTL_CONSTANT_STRING(L"*\\NGS*.SYS"),
      RTL_CONSTANT_STRING(L"*\\DISPG.SYS"),
  };

  for (auto& expression : kTargetDriverExpressions) {
    if (!FsRtlIsNameInExpression(&expression, full_image_name, TRUE, nullptr)) {
      continue;
    }

    HYPERPLATFORM_COMMON_DBG_BREAK();

    PVOID protected_drv_base = image_info->ImageBase;
    SIZE_T protected_drv_size = image_info->ImageSize;

    HYPERPLATFORM_LOG_INFO("A new driver \"%wZ\" is loaded: %I64X-%I64X \r\n", 
      full_image_name,
      protected_drv_base,
      (char*)protected_drv_base + protected_drv_size);
    HYPERPLATFORM_LOG_INFO("Let's isolate it! \r\n");
    
    HYPERPLATFORM_LOG_INFO("Untrusted driver is being loaded. Add an isolated enclave for it! ");
    HYPERPLATFORM_LOG_INFO("Name: %wZ", full_image_name);
    //RweAddSrcRange(image_info->ImageBase, image_info->ImageSize);

    EptData *new_ept = RweAddIsolatedEnclave(protected_drv_base, protected_drv_size);
    if (new_ept) {
        ShEnablePageShadowingForNewEnclave(new_ept);
        RweApplyRanges();
    } 
    break;
  }
}

//////////////////////////////////////////////////////////////////////////

NTKERNELAPI UCHAR *NTAPI PsGetProcessImageFileName(_In_ PEPROCESS process);

bool TestpIsThisProcessLaunchedByExplorer(HANDLE ProcessId) {
    bool b_res = false;
    PEPROCESS Process = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {
        PCHAR processName = (PCHAR)PsGetProcessImageFileName(Process);
        CHAR explorerexe_name[] = "explorer.exe";
        size_t len = sizeof(explorerexe_name) - 1;
        b_res = (len == RtlCompareMemory(explorerexe_name, processName, len));

        if (Process) {
            ObDereferenceObject(Process);
        }
    }
    return b_res;
}

void TextpAddNewProcessToken(_In_ HANDLE ProcessId, PEPROCESS Process) {
    EPROCESS_PID new_process = { 0 };
    new_process.ProcessId = ProcessId;

    ULONG64 token_addr = *(ULONG64*)((char*)Process + g_EprocOffsets.Token);
    token_addr &= ~0xF; // < clear 4 low bits for the _EX_FAST_REF.RefCnt 
    auto size = 16; // sizeof(TOKEN_SOURCE)

    new_process.mem_token_list.push_back(EPROCESS_FIELD{ (void*)token_addr, size });

    RweAddEprocess(new_process);
}

bool TextpDelEprocessStructs(_In_ HANDLE ProcessId) {
    return RweDelEprocess(ProcessId);
}

_Use_decl_annotations_ void TestpCreateProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process); // unreferenced
    UNREFERENCED_PARAMETER(ProcessId); // unreferenced

                                       //If CreateInfo is non-NULL, a new process is being created
    if (CreateInfo != NULL) {
        UNICODE_STRING cmdexe = RTL_CONSTANT_STRING(L"*\\CMD.EXE");
        if (FsRtlIsNameInExpression(&cmdexe, (PUNICODE_STRING)CreateInfo->ImageFileName, TRUE, nullptr) &&
            TestpIsThisProcessLaunchedByExplorer(CreateInfo->ParentProcessId)) {
            HYPERPLATFORM_COMMON_DBG_BREAK();
            if (NT_SUCCESS(CreateInfo->CreationStatus)) {
                //add_new_eprocess(ProcessId, Process);
                TextpAddNewProcessToken(ProcessId, Process);
                RweApplyRanges();
            }
        }
    }
    // If CreateInfo is NULL, the specified process is exiting.
    else if (TextpDelEprocessStructs(ProcessId)) {
        RweApplyRanges();
    }
}



}  // extern "C"
