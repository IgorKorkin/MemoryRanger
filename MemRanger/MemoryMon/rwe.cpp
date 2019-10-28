// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements RWE functions.

#include "rwe.h"
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/common.h"
#include "../HyperPlatform/log.h"
#include "../HyperPlatform/util.h"
#include "../HyperPlatform/ept.h"
#include "../HyperPlatform/vmm.h"
#include "../HyperPlatform/performance.h"
#include "V2PMap.h"
#include "AddressRanges.h"
#include "InterruptHandlers.h"
#include "mem_trace.h"
#include "mem_ranger_rules.h" // class MemoryRanger
#include "../DdiMon/ddi_mon.h"



#if !defined(_AMD64_)
#error This project does not support x86 yet.
#endif

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// xmmN is 128 bits (memmove etc)
// zmmN is 512 bits (AVX-512)
static const auto kRwepNumOfMonitoredBytesForWrite = 16;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct RweLastData {
  bool is_write;
  bool is_inside_range;
  void* guest_ip;
  void* fault_va;
  EptCommonEntry* ept_entry;
  std::array<UCHAR, kRwepNumOfMonitoredBytesForWrite> old_bytes;
};

struct RweData {
  RweLastData last_data;
};

struct RweSharedData {
  AddressRanges os_internal_drivers_range;   // < a list of OS internal drivers: ntoskrnl.exe, NTFS.sys  etc
  AddressRanges isolated_drivers_range; // < a list with newly loaded drivers: MemAttacker.sys MemAllocator.sys etc 
  AddressRanges os_internal_data_range; // < a list with OS internal drivers, which should be protected

  AddressRanges grant_access_list; // < a list with dynamically allocated data addresses, 
                                   // < which have been freed and are not relevant yet

  AddressRanges file_objects_ranges; // < list of FILE_OBJECT structures, 
                                     //   is used to prevent FILE_OBJECT Hijacking
  AddressRanges handle_table_ranges; // < list of HANDLE_TABLE_ENTRY-ies for all drivers, 
                                     //   is used to prevent HANDLE_TABLE Hijacking

  AddressRanges src_ranges;
  AddressRanges dst_ranges;
  V2PMap2 v2p_map;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

static KDEFERRED_ROUTINE RwepApplyRangesDpcRoutine;

static void RweSwitchToDefaulEnclave(_Inout_ ProcessorData* processor_data);

//static void RwepSwitchToMonitoringMode(_Inout_ ProcessorData* processor_data);

static void RwepHandleExecuteViolation(_Inout_ ProcessorData* processor_data,
                                       _In_ void* fault_va);

static void RwepSetMonitorTrapFlag(_In_ bool enable);

static void RwepSetReadWriteOnPage(_In_ bool allow_read_write,
                                   _Out_ EptCommonEntry* ept_entry);

static void* RwepContextCopyMemory(_Out_ void* destination,
                                   _In_ const void* source, _In_ SIZE_T length);

static void RwepHandleReadWriteViolation(_Inout_ ProcessorData* processor_data,
                                         _In_ void* guest_ip,
                                         _In_ void* fault_va,
                                         _In_ bool is_write);

static NTSTATUS RwepBytesToString(_Out_ char* buffer, _In_ SIZE_T buffer_size,
                                  _In_ const UCHAR* bytes,
                                  _In_ SIZE_T bytes_size);

static void RweHandleReadWriteAllowAccess(
  ProcessorData* processor_data, void* guest_ip, void* fault_va,
  bool is_write);

static void RwepSwitchToProtectedDriverMode(
  void* fault_va,
  ProcessorData* processor_data);

static void RwepSetExecuteOnPage(
  bool allow_execute, EptCommonEntry* ept_entry);

static void RweHandleReadWriteBlockAccessViaMTF(
  ProcessorData* processor_data, void* guest_ip, void* fault_va,
  bool is_write, bool is_inside_range);

void RweHandleMonitorTrapFlagProtectedMemory(
  ProcessorData* processor_data, GpRegisters* gp_regs);

// static bool RwepSrcPageCallback(_In_ void* va, _In_ ULONG64 pa,
//                                 _In_opt_ void* context);
// 
// static bool RwepDstPageCallback(_In_ void* va, _In_ ULONG64 pa,
//                                 _In_opt_ void* context);

// static void* RwepFindSourceAddressForExec(_In_ void* return_addr);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, RweAllocData)
#pragma alloc_text(PAGE, RweFreeData)
#pragma alloc_text(PAGE, RweAllocateNewEnclave)
#pragma alloc_text(PAGE, RweAddIsolatedEnclave)
#pragma alloc_text(PAGE, RwepApplyRangesDpcRoutine)
#pragma alloc_text(PAGE, RweSwitchToDefaulEnclave)
#pragma alloc_text(PAGE, RwepSwitchToProtectedDriverMode)
#pragma alloc_text(PAGE, RwepSetExecuteOnPage)
#pragma alloc_text(PAGE, RwepHandleExecuteViolation)
#pragma alloc_text(PAGE, RwepSetMonitorTrapFlag)
#pragma alloc_text(PAGE, RwepSetReadWriteOnPage)
#pragma alloc_text(PAGE, RwepContextCopyMemory)
#pragma alloc_text(PAGE, RweHandleReadWriteBlockAccessViaMTF)
#pragma alloc_text(PAGE, RweHandleReadWriteAllowAccess)
#pragma alloc_text(PAGE, RwepHandleReadWriteViolation)
#pragma alloc_text(PAGE, RweHandleEptViolation)
#pragma alloc_text(PAGE, RwepBytesToString)
#pragma alloc_text(PAGE, RweHandleMonitorTrapFlagProtectedMemory)

#pragma alloc_text(PAGE, RweSetDefaultEptAttributesForEpt)
#pragma alloc_text(PAGE, RweSetDefaultEptAttributes)
#pragma alloc_text(PAGE, RweApplyRanges)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

void* g_rwe_zero_page;

static RweSharedData g_rwep_shared_data;

static InterruptHandlers g_rwep_int_handlers;

static MemoryRanger memory_ranger;

static EprocessStructs eprocess_structs;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

_Use_decl_annotations_ RweData* RweAllocData() {
  PAGED_CODE();
  const auto data = new RweData;
  data->last_data.is_write = false;
  data->last_data.guest_ip = nullptr;
  data->last_data.fault_va = nullptr;
  data->last_data.ept_entry = nullptr;
  return data;
}

_Use_decl_annotations_ void RweFreeData(RweData* rwe_data) {
  PAGED_CODE();
  delete rwe_data;
}

//////////////////////////////////////////////////////////////////////////

bool ShEnablePageShadowingForNewEnclave(EptData* new_ept) {
  bool b_res = false;
  b_res = NT_SUCCESS(UtilVmCall(HypercallNumber::kMemRangerSetEptNewDriver, new_ept));
  return b_res;
}

EptData* RweAllocateNewEnclave() {
  EptData* new_ept = EptInitialization();
  if (new_ept){
    RweSetDefaultEptAttributesForEpt(new_ept);
    return new_ept;
  }
  return nullptr;
}

_Use_decl_annotations_ EptData* RweAddIsolatedEnclave(_In_ void* address, _In_ SIZE_T size) {
  EptData* new_ept = RweAllocateNewEnclave();
  if (new_ept) {
    const auto end_address =
      reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
    HYPERPLATFORM_LOG_INFO_SAFE("Add Isolated Driver's Range: %p - %p", address, end_address);
    memory_ranger.add_driver_enclave(new_ept, address, size);
    g_rwep_shared_data.isolated_drivers_range.add(address, size);
    g_rwep_shared_data.v2p_map.add(address, size);
    return new_ept;
  }
  return nullptr;
}
//////////////////////////////////////////////////////////////////////////

void RweConstructTablesForEnclaves(_In_ TConstructCallback construct_callback,
  ULONG table_level, ULONG64 physical_address, bool default_access) {
   memory_ranger.for_each_ept(construct_callback, table_level, physical_address, default_access);
}
//////////////////////////////////////////////////////////////////////////

_Use_decl_annotations_ void RweAddSrcRange(void* address, SIZE_T size) {
  const auto end_address =
      reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  HYPERPLATFORM_LOG_INFO_SAFE("Add SRC range: %p - %p", address, end_address);
  g_rwep_shared_data.src_ranges.add(address, size);
  g_rwep_shared_data.v2p_map.add(address, size);
}

_Use_decl_annotations_ void RweAddDstRange(void* address, SIZE_T size) {
  const auto end_address =
      reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  HYPERPLATFORM_LOG_INFO_SAFE("Add DST range: %p - %p", address, end_address);
  g_rwep_shared_data.dst_ranges.add(address, size);
  g_rwep_shared_data.v2p_map.add(address, size);
}

_Use_decl_annotations_ void RweAddOneOSInternalDriverRange(void* address, SIZE_T size) {
  const auto end_address =
    reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  HYPERPLATFORM_LOG_INFO_SAFE("Add ProtectedDrv range: %p - %p", address, end_address);
  g_rwep_shared_data.os_internal_drivers_range.add(address, size);
  g_rwep_shared_data.v2p_map.add(address, size);
}

_Use_decl_annotations_ void RweAddOneOSInternalDataRange(void* address, SIZE_T size) {
  const auto end_address =
    reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  HYPERPLATFORM_LOG_INFO_SAFE("Add range for OS internal structures: %p - %p", address, end_address);
  g_rwep_shared_data.os_internal_data_range.add(address, size);
  g_rwep_shared_data.v2p_map.add(address, size);
}

_Use_decl_annotations_ void RweAddEprocess(const EPROCESS_PID & proc) {
  return eprocess_structs.add(proc, RweAddOneOSInternalDataRange);
}

/*  */
_Use_decl_annotations_ void RweAddFileObjRange(void* address, SIZE_T size) {
  const auto end_address =
    reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  HYPERPLATFORM_LOG_INFO_SAFE("Add FILE_OBJECT %p - %p to the list", address, end_address);
  g_rwep_shared_data.file_objects_ranges.add(address, size);
  g_rwep_shared_data.v2p_map.add(address, size);
}

/*  */
_Use_decl_annotations_ void RweAddHandleEntryRange(void* address, SIZE_T size) {
  const auto end_address =
    reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  HYPERPLATFORM_LOG_INFO_SAFE("Add HANDLE_TABLE_ENTRY %p - %p to the list", address, end_address);
  g_rwep_shared_data.handle_table_ranges.add(address, size);
  g_rwep_shared_data.v2p_map.add(address, size);
}

bool RweAddHandleTableEntryForNewlyLoadedDriver(void* driverAddr, void* handleTableEntry) {
  const SIZE_T handle_entry_zs = (OBJECTPOINTERBITS_SIZE);
  if (memory_ranger.add_handle_entry(driverAddr, handleTableEntry, handle_entry_zs)) {
    RweAddHandleEntryRange(handleTableEntry, handle_entry_zs); // < Mark memory region as non-readable and non-writable )
    return true;
  }
  return false;
}

//////////////////////////////////////////////////////////////////////////

_Use_decl_annotations_ void RweDelOneOSInternalDataRange(void* address, SIZE_T size) {
  const auto end_address =
    reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  HYPERPLATFORM_LOG_INFO_SAFE("The range for OS internal structures %p - %p has been deleted", address, end_address);

  g_rwep_shared_data.os_internal_data_range.del(address, size);
  g_rwep_shared_data.v2p_map.del(address, size);

  g_rwep_shared_data.grant_access_list.add(address, size);
}

_Use_decl_annotations_ bool RweDelEprocess(const HANDLE ProcessId) {
  return eprocess_structs.del(ProcessId, RweDelOneOSInternalDataRange);
}


_Use_decl_annotations_ bool RweDelFileObject(void* driverAddress, void* fileobjAddr) {
  auto size = memory_ranger.del_file_object(driverAddress, fileobjAddr);
  if (size) {
    g_rwep_shared_data.file_objects_ranges.del(fileobjAddr, size);
    g_rwep_shared_data.v2p_map.del(fileobjAddr, size);

    g_rwep_shared_data.grant_access_list.add(fileobjAddr, size);

    HYPERPLATFORM_LOG_INFO_SAFE("The FILE_OBJECT %p by %p driver has been deleted.", fileobjAddr, driverAddress);
    return true;
  }
  return false;
}


_Use_decl_annotations_ bool RweDelHandleTableEntry(void* driverAddress, void* handleEntry) {
  auto size = memory_ranger.del_handle_entry(driverAddress, handleEntry);
  if (size) {
    g_rwep_shared_data.handle_table_ranges.del(handleEntry, size);
    g_rwep_shared_data.v2p_map.del(handleEntry, size);

    g_rwep_shared_data.grant_access_list.add(handleEntry, size);

    HYPERPLATFORM_LOG_INFO_SAFE("The HANDLE_TABLE_ENTRY %p by %p driver has been deleted.", handleEntry, driverAddress);
    return true;
  }
  return false;
}

//////////////////////////////////////////////////////////////////////////



_Use_decl_annotations_ bool RweIsInsideSrcRange(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.src_ranges.is_in_range(address);
}

_Use_decl_annotations_ bool RweIsInsideDstRange(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.dst_ranges.is_in_range(address);
}

bool RweIsInsideOSInternalDriversRange(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.os_internal_drivers_range.is_in_range(address);
}

_Use_decl_annotations_ bool RweIsInsideNewlyLoadedDriversRange(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.isolated_drivers_range.is_in_range(address);
}

_Use_decl_annotations_ bool RweIsInsideNewlyLoadedDriversRangePageAlign(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.isolated_drivers_range.is_in_range_page_align(address);
}

_Use_decl_annotations_ bool RweIsInsideOSInternalDataRange(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.os_internal_data_range.is_in_range(address);
}

_Use_decl_annotations_ bool RweIsInsideOSInternalDataRangePageAlign(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.os_internal_data_range.is_in_range_page_align(address);
}

_Use_decl_annotations_ bool RweIsInsideFileObjectsRange(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.file_objects_ranges.is_in_range(address);
}

/**/
_Use_decl_annotations_ bool RweIsInsideFileObjectsRangePageAlign(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.file_objects_ranges.is_in_range_page_align(address);
}

_Use_decl_annotations_ bool RweIsInsideHandleTableRange(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.handle_table_ranges.is_in_range(address);
}

_Use_decl_annotations_ bool RweIsInsideHandleTableRangePageAlign(void* address) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  return g_rwep_shared_data.handle_table_ranges.is_in_range_page_align(address);
}

//////////////////////////////////////////////////////////////////////////

void RweRefreshTables(ProcessorData* processor_data, ULONG64 physical_address, void* virtual_address) {

  for (auto & each_driver : memory_ranger.protected_memory_list) {
    if (each_driver.ept) {
      auto ept_entry = EptGetEptPtEntry(each_driver.ept, physical_address);
      if (RweIsInsideOSInternalDriversRange(virtual_address)) {
        bool res_ddimon = ShpIsItHookAddress(processor_data->shared_data->shared_sh_data, virtual_address);
        if (res_ddimon) {
            ept_entry->fields.execute_access = true;
            ept_entry->fields.read_access = false;
            ept_entry->fields.write_access = false;
        }
        else {
          ept_entry->fields.execute_access = true;
          ept_entry->fields.read_access = true;
          ept_entry->fields.write_access = true;
        }
      }
      else if (RweIsInsideNewlyLoadedDriversRange(virtual_address)) {
        if (UtilIsInBounds(virtual_address, each_driver.driverStart, each_driver.driverEnd)) {
          ept_entry->fields.execute_access = true;
          ept_entry->fields.read_access = true;
          ept_entry->fields.write_access = true;
        }
        else {
          ept_entry->fields.execute_access = false;
          ept_entry->fields.read_access = false;
          ept_entry->fields.write_access = false;
        }
      }
      else if (RweIsInsideOSInternalDataRange(virtual_address)) {
        __debugbreak();
        ept_entry->fields.execute_access = false;
        ept_entry->fields.read_access = false;
        ept_entry->fields.write_access = false;
      }
      else if (RweIsInsideHandleTableRange(virtual_address)) {
        HYPERPLATFORM_COMMON_DBG_BREAK();
        ept_entry->fields.execute_access = true;
        ept_entry->fields.read_access = true;
        ept_entry->fields.write_access = true;
      }
      else {
        // pages are not accessible by default
        ept_entry->fields.execute_access = false;
        ept_entry->fields.read_access = false;
        ept_entry->fields.write_access = false;
      }
    }
  }
}


//////////////////////////////////////////////////////////////////////////


// Make all non-executable for MONITOR
_Use_decl_annotations_ void RweSetDefaultEptAttributes(
    ProcessorData* processor_data) {
  PAGED_CODE();

  const auto pm_ranges = UtilGetPhysicalMemoryRanges();
  for (auto run_index = 0ul; run_index < pm_ranges->number_of_runs;
       ++run_index) {
    const auto run = &pm_ranges->run[run_index];
    const auto base_addr = run->base_page * PAGE_SIZE;
    for (auto page_index = 0ull; page_index < run->page_count; ++page_index) {
      const auto indexed_addr = base_addr + page_index * PAGE_SIZE;
      const auto ept_entry =
          EptGetEptPtEntry(processor_data->ept_data_protected_driver, indexed_addr);

      ept_entry->fields.execute_access = false;
    }
  }
}

_Use_decl_annotations_ void RweSetDefaultEptAttributesForEpt(
  EptData *ept_data) {
  PAGED_CODE();

  const auto pm_ranges = UtilGetPhysicalMemoryRanges();
  for (auto run_index = 0ul; run_index < pm_ranges->number_of_runs;
    ++run_index) {
    const auto run = &pm_ranges->run[run_index];
    const auto base_addr = run->base_page * PAGE_SIZE;
    for (auto page_index = 0ull; page_index < run->page_count; ++page_index) {
      const auto indexed_addr = base_addr + page_index * PAGE_SIZE;
      const auto ept_entry =
        EptGetEptPtEntry(ept_data, indexed_addr);

      ept_entry->fields.execute_access = false;
    }
  }
}

// Apply ranges to EPT attributes
_Use_decl_annotations_ void RweApplyRanges() {
  PAGED_CODE();

  UtilForEachProcessor(
      [](void* context) {
        UNREFERENCED_PARAMETER(context);
        return UtilVmCall(HypercallNumber::kRweApplyRanges, nullptr);
      },
      nullptr);
}

// Set a va associated with 0xfd5fa000 as a dest range
_Use_decl_annotations_ void RweHandleNewDeviceMemoryAccess(ULONG64 pa,
                                                           void* va) {
  if (MemTraceIsTargetDstAddress(pa)) {
    RweAddDstRange(PAGE_ALIGN(va), PAGE_SIZE);
  }
}

_Use_decl_annotations_ static void RwepApplyRangesDpcRoutine(
    _KDPC* dpc, PVOID deferred_context, PVOID system_argument1,
    PVOID system_argument2) {

  UNREFERENCED_PARAMETER(deferred_context);
  UNREFERENCED_PARAMETER(system_argument1);
  UNREFERENCED_PARAMETER(system_argument2);

  UtilVmCall(HypercallNumber::kRweApplyRanges, nullptr);
  if (dpc){
    ExFreePoolWithTag(dpc, kHyperPlatformCommonPoolTag);
  }
  
}

/*token*/
_Use_decl_annotations_ static void RweSwitchToTokenEnclave(
    ProcessorData* processor_data) {
    processor_data->ept_data = processor_data->ept_data_token;
    UtilVmWrite64(VmcsField::kEptPointer,
        EptGetEptPointer(processor_data->ept_data));
    HYPERPLATFORM_LOG_DEBUG_SAFE("DEFAULT ENCLAVE => TOKEN ENCLAVE");
    UtilInveptGlobal();
}

_Use_decl_annotations_ static void RweSwitchToDefaulEnclave(
    ProcessorData* processor_data) {
  processor_data->ept_data = processor_data->ept_data_default_enclave;
  UtilVmWrite64(VmcsField::kEptPointer,
                EptGetEptPointer(processor_data->ept_data));
   HYPERPLATFORM_LOG_DEBUG_SAFE(" NON DEFAULT ENCLAVE => DEFAULT ENCLAVE");
  UtilInveptGlobal();
}

_Use_decl_annotations_ static void RwepSwitchToProtectedDriverMode(
  void* fault_va,
  ProcessorData* processor_data) {
  EptData * ept = memory_ranger.get_drivers_ept(fault_va);
  if (!ept) { ept = memory_ranger.access_to_the_allocated_data(fault_va); }
  if (!ept) { ept = memory_ranger.access_to_the_file_object(fault_va); }
  if (!ept) { ept = memory_ranger.access_to_the_handle_table(fault_va); }
  if (!ept) { HYPERPLATFORM_COMMON_DBG_BREAK(); }
  processor_data->ept_data = ept;
  UtilVmWrite64(VmcsField::kEptPointer,
    EptGetEptPointer(processor_data->ept_data));
  HYPERPLATFORM_LOG_DEBUG_SAFE("DEFAULT  => PROTECTED");
  UtilInveptGlobal();
}

// _Use_decl_annotations_ static void RwepSwitchToMonitoringMode(
//     ProcessorData* processor_data) {
//   processor_data->ept_data = processor_data->ept_data_monitor;
//   UtilVmWrite64(VmcsField::kEptPointer,
//                 EptGetEptPointer(processor_data->ept_data));
//   // HYPERPLATFORM_LOG_DEBUG_SAFE("NORMAL  => MONITOR");
//   UtilInveptGlobal();
// }

// _Use_decl_annotations_ static void* RwepFindSourceAddressForExec(
//     void* return_addr) {
//   const auto current_cr3 = __readcr3();
//   const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
//   __writecr3(guest_cr3);
// 
//   UCHAR code[10] = {};
//   auto is_executable = UtilIsExecutableAddress(return_addr);
//   if (is_executable) {
//     const auto disasseble_addr =
//         reinterpret_cast<UCHAR*>(return_addr) - sizeof(code);
//     if (PAGE_ALIGN(return_addr) != PAGE_ALIGN(disasseble_addr)) {
//       is_executable = UtilIsExecutableAddress(disasseble_addr);
//     }
//     if (is_executable) {
//       RtlCopyMemory(code, disasseble_addr, sizeof(code));
//     }
//   }
// 
//   __writecr3(current_cr3);
//   if (!is_executable) {
//     return nullptr;
//   }
// 
//   auto offset = 0ul;
//   if (code[5] == 0xe8) {  // e8 xx xx xx xx   // common
//     offset = sizeof(code) - 5;
//   } else if (code[4] == 0xff) {  // ff xx xx xx xx xx   // common
//     offset = sizeof(code) - 4;
//   } else if (code[8] == 0xff) {  // ff xx
//     offset = sizeof(code) - 8;
//   } else if (code[7] == 0xff) {  // ff xx xx
//     offset = sizeof(code) - 7;
//   } else if (code[6] == 0xff) {  // ff xx xx xx
//     offset = sizeof(code) - 6;
//   } else if (code[3] == 0xff) {  // ff xx xx xx xx xx xx
//     offset = sizeof(code) - 3;
//   } else {
//     return nullptr;
//   }
// 
//   if (offset) {
//     return reinterpret_cast<UCHAR*>(return_addr) - offset;
//   } else {
//     return return_addr;
//   }
// }

//////////////////////////////////////////////////////////////////////////

_Use_decl_annotations_ static void RwepSetExecuteOnPage(
  bool allow_execute, EptCommonEntry* ept_entry) {
  ept_entry->fields.execute_access = allow_execute;
  UtilInveptGlobal();
}

_Use_decl_annotations_ static void RwepHandleExecuteViolation(
  ProcessorData* processor_data, void* fault_va) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

  if (processor_data->ept_data == processor_data->ept_data_default_enclave) {
    if (RweIsInsideNewlyLoadedDriversRange(fault_va)) {
      RwepSwitchToProtectedDriverMode(fault_va, processor_data);
    }
    else {
      // Sometimes the address is not marked as executable for some reasons
      const auto ept_entry = EptGetEptPtEntry(
        processor_data->ept_data, UtilVmRead64(VmcsField::kGuestPhysicalAddress));
      RwepSetExecuteOnPage(true, ept_entry);
    }
  }
  else {
    if (RweIsInsideNewlyLoadedDriversRange(fault_va)) {
      if (memory_ranger.get_drivers_ept(fault_va) == processor_data->ept_data) {
        bool access_from_my_driver = RweIsInsideNewlyLoadedDriversRange(fault_va);
        bool access_from_system = RweIsInsideOSInternalDriversRange(fault_va);
        if (access_from_my_driver || access_from_system) {
          __debugbreak();
        }
        //Sometimes the address is not marked as executable for some reasons
        const auto ept_entry = EptGetEptPtEntry(
          processor_data->ept_data, UtilVmRead64(VmcsField::kGuestPhysicalAddress));
        RwepSetExecuteOnPage(true, ept_entry);
      }
      else {
        RwepSwitchToProtectedDriverMode(fault_va, processor_data);
      }
    }
    else {
      RweSwitchToDefaulEnclave(processor_data);
    }
  }

//   const auto guest_sp = reinterpret_cast<void**>(UtilVmRead(VmcsField::kGuestRsp));
//   void* return_address = nullptr;
//   RwepContextCopyMemory(&return_address, guest_sp, sizeof(void*));
// 
//   // Log only when a return address is inside a source range. By this, we
//   // ignore following cases:
//   //    - RET from a source range to other range
//   //    - conditional and unconditional jump from a source range to other
//   //    range
//   if (!RweIsInsideIsolatedDriversRange(return_address)) {
//     return;
//   }
//   const auto fault_base = UtilPcToFileHeader(fault_va);
//   const auto is_interrupt = g_rwep_int_handlers.has(fault_va);
//   const auto src_addr = (is_interrupt)
//     ? return_address
//     : RwepFindSourceAddressForExec(return_address);
// 
//   if (!src_addr) {
//     HYPERPLATFORM_LOG_DEBUG_SAFE(
//       "R= ---------------- (----------------), D= %p (%p), T= E", fault_va,
//       fault_base);
//   }
//   else if (is_interrupt || src_addr != return_address) {
//     const auto src_base = UtilPcToFileHeader(src_addr);
//     HYPERPLATFORM_LOG_INFO_SAFE("S= %p (%p), D= %p (%p), T= E", src_addr,
//       src_base, fault_va, fault_base);
//   }
//   else {
//     const auto return_base = UtilPcToFileHeader(return_address);
//     HYPERPLATFORM_LOG_INFO_SAFE("R= %p (%p), D= %p (%p), T= E",
//       return_address, return_base, fault_va,
//       fault_base);
//   }
}


// _Use_decl_annotations_ static void RwepHandleExecuteViolation(
//     ProcessorData* processor_data, void* fault_va) {
//   HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
// 
//   if (RweIsInsideSrcRange(fault_va)) {
//     // Someone is entering a source range
//     // NT_ASSERT(processor_data->ept_data == processor_data->ept_data_normal);
// 
//     // Sometimes the address is not marked as executable for some reasons
//     // This is only for Monitoring Mode
//     if (processor_data->ept_data != processor_data->ept_data_default_enclave) {
//       const auto ept_entry =
//           EptGetEptPtEntry(processor_data->ept_data,
//                            UtilVmRead64(VmcsField::kGuestPhysicalAddress));
//       ept_entry->fields.execute_access = true;
//     }
// 
//     // Currently
//     //        E   RW
//     //  Src   x   o
//     //  Dst   o   o
//     //  Oth   o   o
//     NT_ASSERT(!RweIsInsideDstRange(fault_va));
// 
//     // Switch to
//     //        E   RW
//     //  Src   o   o
//     //  Dst   x   x
//     //  Oth   x   o
//     RwepSwitchToMonitoringMode(processor_data);
// 
//     if (MemTraceIsEnabled()) {
//       return;
//     }
//     const auto guest_sp =
//         reinterpret_cast<void**>(UtilVmRead(VmcsField::kGuestRsp));
//     void* return_address = nullptr;
//     RwepContextCopyMemory(&return_address, guest_sp, sizeof(void*));
// 
//     const auto fault_base = UtilPcToFileHeader(fault_va);
//     const auto is_interrupt = g_rewp_int_handlers.has(fault_va);
//     const auto src_addr = (is_interrupt)
//                               ? return_address
//                               : RwepFindSourceAddressForExec(return_address);
// 
//     if (!src_addr) {
//       HYPERPLATFORM_LOG_DEBUG_SAFE(
//           "R= ---------------- (----------------), D= %p (%p), T= E", fault_va,
//           fault_base);
//     } else if (is_interrupt || src_addr != return_address) {
//       const auto src_base = UtilPcToFileHeader(src_addr);
//       HYPERPLATFORM_LOG_DEBUG_SAFE("S= %p (%p), D= %p (%p), T= E", src_addr,
//                                    src_base, fault_va, fault_base);
//     } else {
//       const auto return_base = UtilPcToFileHeader(return_address);
//       HYPERPLATFORM_LOG_DEBUG_SAFE("R= %p (%p), D= %p (%p), T= E",
//                                    return_address, return_base, fault_va,
//                                    fault_base);
//     }
// 
//   } else {
//     // Presumably, someone is leaving a source range
//     NT_ASSERT(processor_data->ept_data == processor_data->ept_data_monitor);
// 
//     // Currently
//     //        E   RW
//     //  Src   o   o
//     //  Dst   x   x
//     //  Oth   x   o
// 
//     // Switch to
//     //        E   RW
//     //  Src   x   o
//     //  Dst   o   o
//     //  Oth   o   o
//     RweSwitchToDefaulEnclave(processor_data);
// 
//     if (MemTraceIsEnabled()) {
//       return;
//     }
//     const auto guest_sp =
//         reinterpret_cast<void**>(UtilVmRead(VmcsField::kGuestRsp));
//     void* return_address = nullptr;
//     RwepContextCopyMemory(&return_address, guest_sp, sizeof(void*));
// 
//     // Log only when a return address is inside a source range. By this, we
//     // ignore following cases:
//     //    - RET from a source range to other range
//     //    - conditional and unconditional jump from a source range to other
//     //    range
//     if (!RweIsInsideSrcRange(return_address)) {
//       return;
//     }
//     const auto fault_base = UtilPcToFileHeader(fault_va);
//     const auto is_interrupt = g_rewp_int_handlers.has(fault_va);
//     const auto src_addr = (is_interrupt)
//                               ? return_address
//                               : RwepFindSourceAddressForExec(return_address);
// 
//     if (!src_addr) {
//       HYPERPLATFORM_LOG_DEBUG_SAFE(
//           "R= ---------------- (----------------), D= %p (%p), T= E", fault_va,
//           fault_base);
//     } else if (is_interrupt || src_addr != return_address) {
//       const auto src_base = UtilPcToFileHeader(src_addr);
//       HYPERPLATFORM_LOG_INFO_SAFE("S= %p (%p), D= %p (%p), T= E", src_addr,
//                                   src_base, fault_va, fault_base);
//     } else {
//       const auto return_base = UtilPcToFileHeader(return_address);
//       HYPERPLATFORM_LOG_INFO_SAFE("R= %p (%p), D= %p (%p), T= E",
//                                   return_address, return_base, fault_va,
//                                   fault_base);
//     }
//   }
// }



_Use_decl_annotations_ static void RwepSetMonitorTrapFlag(bool enable) {
  VmxProcessorBasedControls vm_procctl = {
      static_cast<unsigned int>(UtilVmRead(VmcsField::kCpuBasedVmExecControl))};
  vm_procctl.fields.monitor_trap_flag = enable;
  UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
}

_Use_decl_annotations_ static void RwepSetReadWriteOnPage(
    bool allow_read_write, EptCommonEntry* ept_entry) {
  if (ept_entry){
    ept_entry->fields.write_access = allow_read_write;
    ept_entry->fields.read_access = allow_read_write;
  }  
  UtilInveptGlobal();
}

_Use_decl_annotations_ static void* RwepContextCopyMemory(void* destination,
                                                          const void* source,
                                                          SIZE_T length) {
  const auto current_cr3 = __readcr3();
  const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
  __writecr3(guest_cr3);
  const auto result = RtlCopyMemory(destination, source, length);
  __writecr3(current_cr3);
  return result;
}

//////////////////////////////////////////////////////////////////////////


_Use_decl_annotations_ static void RweHandleReadWriteBlockAccessViaMTF(
  ProcessorData* processor_data, void* guest_ip, void* fault_va,
  bool is_write, bool is_inside_range) {
  // block access to this page using MTF

  // Anyway it is needed to allow access to this memory
  const auto ept_entry = EptGetEptPtEntry(
    processor_data->ept_data, UtilVmRead64(VmcsField::kGuestPhysicalAddress));
  RwepSetReadWriteOnPage(true, ept_entry);

  RwepSetMonitorTrapFlag(true);
  // Check that somebody tries read- or write to protected memory
  // is_inside_range

  // Save data to process them in MTF-handler 
  processor_data->rwe_data->last_data.is_write = is_write;
  processor_data->rwe_data->last_data.is_inside_range = is_inside_range;
  processor_data->rwe_data->last_data.guest_ip = guest_ip;
  processor_data->rwe_data->last_data.fault_va = fault_va;
  processor_data->rwe_data->last_data.ept_entry = ept_entry;
  if (!is_inside_range) {
    // Non-sensitive data, which is located at the same memory PAGE with the protected data
    // has been accessed 
    return;
  }

  if (is_write) {
    // save the memory connect to print them in RweHandleMonitorTrapFlag
    RwepContextCopyMemory(
      processor_data->rwe_data->last_data.old_bytes.data(),
      reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(fault_va) & ~0xf),
      processor_data->rwe_data->last_data.old_bytes.size());
  }
  else {
    processor_data->rwe_data->last_data.old_bytes.fill(0);
  }

  if (is_write) {
    HYPERPLATFORM_LOG_INFO_SAFE(
      "Memory Ranger: illegal WRITE access has been trapped from %I64X to %I64X ",
      guest_ip, fault_va);
  }
  if (!is_write) {
    HYPERPLATFORM_LOG_INFO_SAFE(
      "Memory Ranger: illegal READ access has been trapped from %I64X to %I64X ",
      guest_ip, fault_va);
  }
  HYPERPLATFORM_LOG_INFO_SAFE("Memory Ranger changes PFN to prevent this access");
  RtlSecureZeroMemory(g_rwe_zero_page, PAGE_SIZE);
  const auto pfn = UtilPfnFromVa(g_rwe_zero_page);
  ept_entry->fields.physial_address = pfn;
  UtilInveptGlobal(); // to force update EPT cache 
}


_Use_decl_annotations_ static void RweHandleReadWriteAllowAccess(
  ProcessorData* processor_data, void* guest_ip, void* fault_va,
  bool is_write) {
  // allow access to the data
  const auto ept_entry = EptGetEptPtEntry(
    processor_data->ept_data, UtilVmRead64(VmcsField::kGuestPhysicalAddress));
  RwepSetReadWriteOnPage(true, ept_entry);
  if (is_write) {
    HYPERPLATFORM_LOG_INFO_SAFE(
      "Memory Ranger: WRITE access %I64X [%I64X] to %I64X [%I64X] *** *** ",
      guest_ip, (UtilPcToFileHeader(guest_ip)), fault_va, (UtilPcToFileHeader(fault_va)));
  }
  else {
    HYPERPLATFORM_LOG_INFO_SAFE(
      "Memory Ranger: READ access %I64X [%I64X] to %I64X [%I64X] *** *** ",
      guest_ip, (UtilPcToFileHeader(guest_ip)), fault_va, (UtilPcToFileHeader(fault_va)));
  }
}

_Use_decl_annotations_ static void RwepHandleReadWriteFromNonDefaultEnclave(
    ProcessorData* processor_data, void* guest_ip, void* fault_va,
    bool is_write) {

    bool access_to_isol_driver_align = RweIsInsideNewlyLoadedDriversRangePageAlign(fault_va);
    bool access_to_alloc_mem_align = false; // RweIsInsideMemoryAllocationRangePageAlign(fault_va);
    bool access_to_os_internal_data_align = RweIsInsideOSInternalDataRangePageAlign(fault_va);
    bool access_to_fileobj_align = RweIsInsideFileObjectsRangePageAlign(fault_va);
    bool access_to_handle_entry_align = RweIsInsideHandleTableRangePageAlign(fault_va);


    /* 1 2 3 */

    if (access_to_isol_driver_align || access_to_alloc_mem_align || 
        access_to_fileobj_align || access_to_handle_entry_align) {
        bool access_from_driver = RweIsInsideNewlyLoadedDriversRangePageAlign(guest_ip);

      if (access_from_driver) {
          bool access_to_driver = RweIsInsideNewlyLoadedDriversRange(fault_va);
          bool access_to_pool = false; // RweIsInsideMemoryAllocationRange(fault_va);
          bool access_to_fileobj = RweIsInsideFileObjectsRange(fault_va);
          bool access_to_handle_entry = RweIsInsideHandleTableRange(fault_va);
          bool is_inside_range = access_to_driver || access_to_pool || access_to_fileobj || access_to_handle_entry;
          return RweHandleReadWriteBlockAccessViaMTF(processor_data, guest_ip, fault_va, is_write, is_inside_range);
      }
      else {
        bool access_from_system = RweIsInsideOSInternalDriversRange(guest_ip);
        if (access_from_system) {
          bool access_to_handle_entry = RweIsInsideHandleTableRange(fault_va);
          bool is_inside_range = access_to_handle_entry;
          is_inside_range = false;
          return RweHandleReadWriteBlockAccessViaMTF(processor_data, guest_ip, fault_va, is_write, is_inside_range);
        }
      }
    }
    else if (access_to_os_internal_data_align) {
      bool access_from_system = RweIsInsideOSInternalDriversRange(guest_ip);
      if (access_from_system) {
        return RweSwitchToDefaulEnclave(processor_data);
      }
      else {
        bool access_to_os_internal_data = RweIsInsideOSInternalDataRange(fault_va);
        // Here we have two possible cases:
        // 1) This is illegal access: an attacker's driver tries to access token,  [is_inside_token_range  is  true]
        // block access to the token range
        //
        // or
        // 2) We do not bother, because   [is_inside_token_range  is  false]
        // allow access to the data located at the same page with token
        RweHandleReadWriteBlockAccessViaMTF(processor_data, guest_ip, fault_va, is_write, access_to_os_internal_data);
    }
  }
  else {
    HYPERPLATFORM_LOG_INFO_SAFE("Memory Ranger: WTF ACCESS from isolated enclave ");
    RweHandleReadWriteAllowAccess(processor_data, guest_ip, fault_va, is_write);
  }
}

_Use_decl_annotations_ static void RwepHandleReadWriteFromDefaultEnclave(
    ProcessorData* processor_data, void* guest_ip, void* fault_va,
    bool is_write) {
    bool access_to_isol_driver_align = RweIsInsideNewlyLoadedDriversRangePageAlign(fault_va);
    bool access_to_os_internal_data_align = RweIsInsideOSInternalDataRangePageAlign(fault_va);
    bool access_to_alloc_mem_align = false;//RweIsInsideMemoryAllocationRangePageAlign(fault_va);
    bool access_to_fileobj_align = RweIsInsideFileObjectsRangePageAlign(fault_va);
    bool access_to_handle_entry_align = RweIsInsideHandleTableRangePageAlign(fault_va);

    if (access_to_isol_driver_align || access_to_alloc_mem_align ||
      access_to_fileobj_align || access_to_handle_entry_align) {
        bool access_from_system = RweIsInsideOSInternalDriversRange(guest_ip);
        if (access_from_system) {
          bool access_to_alloc_mem = false; // RweIsInsideMemoryAllocationRange(fault_va);
          bool access_to_fileobj = RweIsInsideFileObjectsRange(fault_va);
          bool access_to_handle_entry = RweIsInsideHandleTableRange(fault_va);
            if (access_to_alloc_mem || access_to_fileobj || access_to_handle_entry) {
                RwepSwitchToProtectedDriverMode(fault_va, processor_data);
            }
            else {
                bool is_inside_range = access_to_alloc_mem || access_to_fileobj || access_to_handle_entry;
                RweHandleReadWriteBlockAccessViaMTF(processor_data, guest_ip, fault_va, is_write, is_inside_range);
            }
        }
        else {
            bool access_to_isol_driver = RweIsInsideNewlyLoadedDriversRange(fault_va);
            bool access_to_alloc_mem = false; // RweIsInsideMemoryAllocationRange(fault_va);
            bool access_to_fileobj = RweIsInsideFileObjectsRange(fault_va);
            bool access_to_handle_entry = RweIsInsideHandleTableRange(fault_va);
            bool is_inside_range = access_to_isol_driver || access_to_alloc_mem || access_to_fileobj || access_to_handle_entry;
            RweHandleReadWriteBlockAccessViaMTF(processor_data, guest_ip, fault_va, is_write, is_inside_range);
        }
    }
    else if (access_to_os_internal_data_align) {
      bool access_to_os_internal_data = RweIsInsideOSInternalDataRange(fault_va);
      if (access_to_os_internal_data) {
        bool access_from_system = RweIsInsideOSInternalDriversRange(guest_ip);
        if (access_from_system) {
          // This is legal access: An OS driver tries to access token from the default enclave
          return RweSwitchToTokenEnclave(processor_data);
        }
        else { 
          // This is illegal access: an attacker's driver tries to access token,  [is_inside_token_range  is  true]
          // block access to the token range
          bool is_inside_range = access_to_os_internal_data;
          RweHandleReadWriteBlockAccessViaMTF(processor_data, guest_ip, fault_va, is_write, is_inside_range);
        }
      }
      else {
        // we do not bother, because   [is_inside_token_range  is  false]
        // allow access to the data located at the same page with token
        bool is_inside_range = access_to_os_internal_data;
        RweHandleReadWriteBlockAccessViaMTF(processor_data, guest_ip, fault_va, is_write, is_inside_range);
      }
    }
    else {
        HYPERPLATFORM_LOG_INFO_SAFE("Memory Ranger: WTF DEF ACCESS from the Default Enclave");
        RweHandleReadWriteAllowAccess(processor_data, guest_ip, fault_va, is_write);
    }
}


_Use_decl_annotations_ static void RwepHandleReadWriteViolation(
  ProcessorData* processor_data, void* guest_ip, void* fault_va,
  bool is_write) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

  if (processor_data->ept_data != processor_data->ept_data_default_enclave) {
      return RwepHandleReadWriteFromNonDefaultEnclave(processor_data, guest_ip, fault_va, is_write);
  }

  else if (processor_data->ept_data == processor_data->ept_data_default_enclave) {
      return RwepHandleReadWriteFromDefaultEnclave(processor_data, guest_ip, fault_va, is_write);
  }
}

// _Use_decl_annotations_ static void RwepHandleReadWriteViolation(
//     ProcessorData* processor_data, void* guest_ip, void* fault_va,
//     bool is_write) {
//   HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
//   NT_ASSERT(!processor_data->rwe_data->last_data.ept_entry);
// 
//   // Read or write from a source range to a dest range
//   //NT_ASSERT(RweIsInsideSrcRange(guest_ip));
//  // NT_ASSERT(processor_data->ept_data == processor_data->ept_data_monitor);
// 
//   if (processor_data->ept_data == processor_data->ept_data_default_enclave){
//     RweHandleReadWriteAllowAccess(processor_data, guest_ip, fault_va, is_write);
//     return;
//   }
// 
//   // Currently
//   //        E   RW
//   //  Src   o   o
//   //  Dst   x   x
//   //  Oth   x   o
// 
//   // most of cases. if the operation happed just outside, may be not
//   const auto is_inside_range = RweIsInsideDstRange(fault_va);
// 
//   const auto ept_entry = EptGetEptPtEntry(
//       processor_data->ept_data, UtilVmRead64(VmcsField::kGuestPhysicalAddress));
// 
//   // Temporarily switch to
//   //        E   RW
//   //  Src   o   o
//   //  Dst   x   o
//   //  Oth   x   o
//   RwepSetReadWriteOnPage(true, ept_entry);
//   HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RWE D:RW- O:RW- %p",
//                                PAGE_ALIGN(fault_va));
//   RwepSetMonitorTrapFlag(true);
// 
//   processor_data->rwe_data->last_data.is_write = is_write;
//   processor_data->rwe_data->last_data.is_inside_range = is_inside_range;
//   processor_data->rwe_data->last_data.guest_ip = guest_ip;
//   processor_data->rwe_data->last_data.fault_va = fault_va;
//   processor_data->rwe_data->last_data.ept_entry = ept_entry;
//   if (is_write) {
//     if (!MemTraceIsEnabled()) {
//       RwepContextCopyMemory(
//           processor_data->rwe_data->last_data.old_bytes.data(),
//           reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(fault_va) & ~0xf),
//           processor_data->rwe_data->last_data.old_bytes.size());
//     }
//   } else {
//     processor_data->rwe_data->last_data.old_bytes.fill(0);
//   }
// 
//   if (!is_write && fault_va == kRwePoolBigPageTableSizeAddress) {
//     // HYPERPLATFORM_COMMON_DBG_BREAK();
//     const auto pfn = UtilPfnFromVa(g_rwe_zero_page);
//     ept_entry->fields.physial_address = pfn;
//     UtilInveptGlobal();
//   }
//   if (!is_write && fault_va == PsInitialSystemProcess) {
//     // HYPERPLATFORM_COMMON_DBG_BREAK();
//     const auto pfn = UtilPfnFromVa(g_rwe_zero_page);
//     ept_entry->fields.physial_address = pfn;
//     UtilInveptGlobal();
//   }
// }


_Use_decl_annotations_ void RweHandleEptViolation(
    ProcessorData* processor_data, void* guest_ip, void* fault_va,
    bool read_violation, bool write_violation, bool execute_violation) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  if (execute_violation) {
    RwepHandleExecuteViolation(processor_data, fault_va);
  } else if (read_violation || write_violation) { 
    if (RweIsInsideOSInternalDriversRange(fault_va)) {
      ShHandleEptViolation(
        processor_data->sh_data,
        processor_data->shared_data->shared_sh_data,
        processor_data->ept_data,
        fault_va);
    }
    else {
      RwepHandleReadWriteViolation(processor_data, guest_ip, fault_va,
        write_violation);
    }
  } else {
    HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
                                   0);
  }
}

_Use_decl_annotations_ static NTSTATUS RwepBytesToString(char* buffer,
                                                         SIZE_T buffer_size,
                                                         const UCHAR* bytes,
                                                         SIZE_T bytes_size) {
  for (auto i = 0ul; i < bytes_size; ++i) {
    const auto consumed_bytes = i * 3;
    const auto remaining_size = buffer_size - consumed_bytes;
    const auto status = RtlStringCchPrintfA(buffer + consumed_bytes,
                                            remaining_size, "%02x ", bytes[i]);
    if (!NT_SUCCESS(status)) {
      NT_ASSERT(false);
      return status;
    }
  }
  buffer[buffer_size - 1] = '\0';
  return STATUS_SUCCESS;
}



_Use_decl_annotations_ void RweHandleMonitorTrapFlagProtectedMemory(
  ProcessorData* processor_data, GpRegisters* gp_regs) {
  UNREFERENCED_PARAMETER(gp_regs);

  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

  // Set page attributes to trap any new access to this page
  RwepSetReadWriteOnPage(false, processor_data->rwe_data->last_data.ept_entry);
  //   if (processor_data->rwe_data->last_data.is_write){
  // 	  RwepSetWriteOnPage(false, processor_data->rwe_data->last_data.ept_entry);
  //   }
  //   else {
  // 	  RwepSetReadOnPage(false, processor_data->rwe_data->last_data.ept_entry);
  //   }

  // Clear MTF to execute code without trapping
  RwepSetMonitorTrapFlag(false);

  if (!processor_data->rwe_data->last_data.is_inside_range) {
    goto end;
  }

  const auto guest_ip_base =
    UtilPcToFileHeader(processor_data->rwe_data->last_data.guest_ip);
  const auto fault_va_base =
    UtilPcToFileHeader(processor_data->rwe_data->last_data.fault_va);

  if (true /*RweShouldWeProtectItbyRules(
           processor_data->rwe_data->last_data.guest_ip,
           processor_data->rwe_data->last_data.fault_va)*/) {

    if (processor_data->rwe_data->last_data.is_write) {
      HYPERPLATFORM_LOG_INFO_SAFE(
        "Memory Ranger: fake data has been OVERWRITTEN ");
    }
    else {
      HYPERPLATFORM_LOG_INFO_SAFE(
        "Memory Ranger: fake data has been READ ");
    }


    //////////////////////////////////////////////////////////////////////////

    if (processor_data->rwe_data->last_data.is_write) {
      static const auto kBinaryStringSize =
        kRwepNumOfMonitoredBytesForWrite * 3 + 1;

      UCHAR new_bytes[kRwepNumOfMonitoredBytesForWrite];
      RwepContextCopyMemory(
        new_bytes, reinterpret_cast<void*>(
          reinterpret_cast<ULONG_PTR>(
            processor_data->rwe_data->last_data.fault_va) &
          ~0xf),
        sizeof(new_bytes));

      char new_bytes_string[kBinaryStringSize];
      RwepBytesToString(new_bytes_string, sizeof(new_bytes_string), new_bytes,
        sizeof(new_bytes));

      char old_bytes_string[kBinaryStringSize];
      RwepBytesToString(old_bytes_string, sizeof(old_bytes_string),
        processor_data->rwe_data->last_data.old_bytes.data(),
        processor_data->rwe_data->last_data.old_bytes.size());

      HYPERPLATFORM_LOG_INFO_SAFE(
        "S= %p (%p), D= %p (%p), T= W, %s => %s",
        processor_data->rwe_data->last_data.guest_ip, guest_ip_base,
        processor_data->rwe_data->last_data.fault_va, fault_va_base,
        old_bytes_string, new_bytes_string);

      if (processor_data->rwe_data->last_data.fault_va ==
        &HalQuerySystemInformation) {
        const auto fault_va = reinterpret_cast<ULONG_PTR>(
          processor_data->rwe_data->last_data.fault_va);
        const auto guest_ip = reinterpret_cast<ULONG_PTR>(
          processor_data->rwe_data->last_data.guest_ip);
        //
        // We have detected write access to HalDispatchTable[1] from an
        // untrusted driver. Stop the system to prevent further exploitation.
        //
        KeBugCheckEx(HYPERGUARD_VIOLATION,
          0x100d,  // A secure memory region corruption
          fault_va, guest_ip, 0);
      }
    }
    else {
      HYPERPLATFORM_LOG_INFO_SAFE(
        "S= %p (%p), D= %p (%p), T= R",
        processor_data->rwe_data->last_data.guest_ip, guest_ip_base,
        processor_data->rwe_data->last_data.fault_va, fault_va_base);
    }

    //////////////////////////////////////////////////////////////////////////


    // Restore the original EPT.pfn
    HYPERPLATFORM_LOG_INFO_SAFE("Memory Ranger: the PFN has been restored. \r\n");
    HYPERPLATFORM_LOG_INFO_SAFE("Memory Ranger: we have protected memory. \r\n");
    const auto pfn = UtilPfnFromVa(processor_data->rwe_data->last_data.fault_va);
    processor_data->rwe_data->last_data.ept_entry->fields.physial_address =
      pfn;
    UtilInveptGlobal();
  }

  //   MemTraceHandleReadWrite(processor_data->rwe_data->last_data.guest_ip, gp_regs,
  //                           processor_data->rwe_data->last_data.is_write);

end:;
  processor_data->rwe_data->last_data.is_write = false;
  processor_data->rwe_data->last_data.is_inside_range = false;
  processor_data->rwe_data->last_data.guest_ip = 0;
  processor_data->rwe_data->last_data.fault_va = 0;
  processor_data->rwe_data->last_data.ept_entry = nullptr;
  processor_data->rwe_data->last_data.old_bytes.fill(0);
}


_Use_decl_annotations_ void RweHandleMonitorTrapFlag(
  ProcessorData* processor_data, GpRegisters* gp_regs) {
  auto fault_va = processor_data->rwe_data->last_data.fault_va;

  if ( (0==fault_va) || RweIsInsideOSInternalDriversRange(fault_va)) {
    ShHandleMonitorTrapFlag(processor_data->sh_data,
      processor_data->shared_data->shared_sh_data,
      processor_data->ept_data);
  }
  else if (RweIsInsideNewlyLoadedDriversRangePageAlign(fault_va) ||
          RweIsInsideOSInternalDataRangePageAlign(fault_va) ||
          /*RweIsInsideMemoryAllocationRangePageAlign(fault_va) || */
          RweIsInsideFileObjectsRangePageAlign(fault_va) ||
          RweIsInsideHandleTableRangePageAlign(fault_va)) {
    RweHandleMonitorTrapFlagProtectedMemory(processor_data, gp_regs);
  }
}

//////////////////////////////////////////////////////////////////////////


void RweSetOSinternalDriversAccessAttribs(ProcessorData *processor_data, ULONG64 physical_address, PVOID va) {
  for (auto & expression : memory_ranger.protected_memory_list) {
    auto ept_entry = EptGetEptPtEntry(expression.ept, physical_address);

    bool res_ddimon = ShpIsItHookAddress(processor_data->shared_data->shared_sh_data, va);
    if (res_ddimon) {
        //__debugbreak();
        // Do not allow an read-write access to the patched memory, e.g. ExAllocatePoolWithTag
        ept_entry->fields.execute_access = true;
        ept_entry->fields.read_access = false;
        ept_entry->fields.write_access = false;
    }
    else {
        ept_entry->fields.execute_access = true;
        ept_entry->fields.read_access = true;
        ept_entry->fields.write_access = true;
    }
  }
}


// Make System ranges executable for the default pages and executable for
// ProtectedDrivers-pages
_Use_decl_annotations_ static bool RwepOSinternalDriversPageCallback(void* va, ULONG64 pa,
  void* context) {
  if (!context) {
    return false;
  }

  if (!pa) {
    UNREFERENCED_PARAMETER(va);
    HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.", va);
    return true;
  }

  const auto processor_data = reinterpret_cast<ProcessorData*>(context);

  const auto ept_entry_n =
    EptGetEptPtEntry(processor_data->ept_data_default_enclave, pa);

  bool res_ddimon = ShpIsItHookAddress(processor_data->shared_data->shared_sh_data, va);
  if (res_ddimon) {
      //__debugbreak();
      // Do not allow an access to the patched memory, e.g. ExAllocatePoolWithTag
      ept_entry_n->fields.execute_access = true;
      ept_entry_n->fields.read_access = false;
      ept_entry_n->fields.write_access = false;
  }
  else {
    ept_entry_n->fields.execute_access = true;
    ept_entry_n->fields.read_access = true;
    ept_entry_n->fields.write_access = true;
  }
  
  /* token */ const auto ept_entry_token =
      EptGetEptPtEntry(processor_data->ept_data_token, pa);
  if (res_ddimon) {
      //__debugbreak();
      // Do not allow an access to the patched memory, e.g. ExAllocatePoolWithTag
      ept_entry_token->fields.execute_access = true;
      ept_entry_token->fields.read_access = false;
      ept_entry_token->fields.write_access = false;
  }
  else {
      ept_entry_token->fields.execute_access = true;
      ept_entry_token->fields.read_access = true;
      ept_entry_token->fields.write_access = true;
  }

  RweSetOSinternalDriversAccessAttribs(processor_data, pa, va);

  // 	const auto ept_entry_m =
  // 		EptGetEptPtEntry(processor_data->ept_data_protected_driver, pa);
  // 	ept_entry_m->fields.execute_access = true;
  // 	ept_entry_m->fields.read_access = true;
  // 	ept_entry_m->fields.write_access = true;

  // 	HYPERPLATFORM_LOG_DEBUG_SAFE("DEFAULT  : System:RWE  AllocMem:--- %p", PAGE_ALIGN(va));
  // 	HYPERPLATFORM_LOG_DEBUG_SAFE("PROTECTED: System:RWE  AllocMem:RW- %p", PAGE_ALIGN(va));
  return true;
}

//////////////////////////////////////////////////////////////////////////


void RweSetProtectedDriverAccessAttribs(void* virtual_address, ULONG64 physical_address) {
  for (auto & each_driver : memory_ranger.protected_memory_list) {
    auto ept_entry = EptGetEptPtEntry(each_driver.ept, physical_address);
    if (UtilIsInBounds(virtual_address, each_driver.driverStart, each_driver.driverEnd)) {
      ept_entry->fields.execute_access = true;
      ept_entry->fields.read_access = true;
      ept_entry->fields.write_access = true;
    }
    else {
      ept_entry->fields.execute_access = false;
      ept_entry->fields.read_access = false;
      ept_entry->fields.write_access = false;
    }
  }
}

void RweSetSystemStructsAccessAttribs(ULONG64 physical_address) {
  for (auto & expression : memory_ranger.protected_memory_list) {
    auto ept_entry = EptGetEptPtEntry(expression.ept, physical_address);
    ept_entry->fields.execute_access = false;
    ept_entry->fields.read_access = false;
    ept_entry->fields.write_access = false;
  }
}


void RweSetSystemStructsGrantAttribs(ULONG64 physical_address) {
  for (auto & expression : memory_ranger.protected_memory_list) {
    auto ept_entry = EptGetEptPtEntry(expression.ept, physical_address);
    ept_entry->fields.execute_access = true;
    ept_entry->fields.read_access = true;
    ept_entry->fields.write_access = true;
  }
}

bool is_this_fileobj_yours(ISOLATED_MEM_ENCLAVE & driver_enclave, void * fileObj) {
  for (const auto & each_file_obj : driver_enclave.file_objects_list) {
    if (UtilIsInBounds(fileObj, each_file_obj.startAddr, each_file_obj.endAddr)) {
      return true;
    }
  }
  return false;
}

void RweSetFileObjAccessAttribs(void* virtual_address, ULONG64 physical_address) {
  for (auto & each_driver : memory_ranger.protected_memory_list) {
    auto driver_ept = EptGetEptPtEntry(each_driver.ept, physical_address);
    if (is_this_fileobj_yours(each_driver, virtual_address)) {
      driver_ept->fields.execute_access = true;
      driver_ept->fields.read_access = true;
      driver_ept->fields.write_access = true;
    }
    else {
      driver_ept->fields.execute_access = false;
      driver_ept->fields.read_access = false;
      driver_ept->fields.write_access = false;
    }
  }
}


bool is_this_handle_entry_yours(ISOLATED_MEM_ENCLAVE & driver_enclave, void * handleEntry) {
  for (const auto & each_handle_entry : driver_enclave.handle_entry_list) {
    if (UtilIsInBounds(handleEntry, each_handle_entry.startAddr, each_handle_entry.endAddr)) {
      return true;
    }
  }
  return false;
}

void RweSetHandleTableAccessAttribs(void* virtual_address, ULONG64 physical_address) {
  for (auto & each_driver : memory_ranger.protected_memory_list) {
    auto driver_ept = EptGetEptPtEntry(each_driver.ept, physical_address);
    if (is_this_handle_entry_yours(each_driver, virtual_address) &&
      !memory_ranger.two_handle_entries_at_one_page(virtual_address)) {
      driver_ept->fields.execute_access = false /*true*/; // < We need to trap illegal access to driver-related entry
      driver_ept->fields.read_access = false /*true*/; // < We need to trap illegal access to driver-related entry
      driver_ept->fields.write_access = false /*true*/; // < We need to trap illegal access to driver-related entry
    }
    else {
      driver_ept->fields.execute_access = false;
      driver_ept->fields.read_access = false;
      driver_ept->fields.write_access = false;
    }
  }
}

//////////////////////////////////////////////////////////////////////////

// Make Protected Drivers ranges non-executable for the default pages and executable for
// ProtectedDrivers-pages
_Use_decl_annotations_ static bool RwepNewlyLoadedDriversPageCallback(void* va, ULONG64 pa,
  void* context) {
  if (!context) {
    return false;
  }

  if (!pa) {
    UNREFERENCED_PARAMETER(va);
    HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.", va);
    return true;
  }

  const auto processor_data = reinterpret_cast<ProcessorData*>(context);

  const auto ept_entry_n =
    EptGetEptPtEntry(processor_data->ept_data_default_enclave, pa);
  ept_entry_n->fields.execute_access = false;
  ept_entry_n->fields.read_access = false;
  ept_entry_n->fields.write_access = false;

  RweSetProtectedDriverAccessAttribs(va, pa);

  // 	const auto ept_entry_m =
  // 		EptGetEptPtEntry(processor_data->ept_data_protected_driver, pa);
  // 	ept_entry_m->fields.execute_access = true;
  // 	ept_entry_m->fields.read_access = true;
  // 	ept_entry_m->fields.write_access = true;

  // 	HYPERPLATFORM_LOG_DEBUG_SAFE("DEFAULT  : ProtDrv:---  AllocMem:--- %p", PAGE_ALIGN(va));
  // 	HYPERPLATFORM_LOG_DEBUG_SAFE("PROTECTED: ProtDrv:RWE  AllocMem:RW- %p", PAGE_ALIGN(va));
  return true;
}

_Use_decl_annotations_ static bool RwepOSInternalDataPageCallback(void* va, ULONG64 pa,
  void* context) {
  if (!context) {
    return false;
  }

  if (!pa) {
    UNREFERENCED_PARAMETER(va);
    HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.", va);
    return true;
  }

  const auto processor_data = reinterpret_cast<ProcessorData*>(context);

  const auto ept_entry_n =
    EptGetEptPtEntry(processor_data->ept_data_default_enclave, pa);
  ept_entry_n->fields.execute_access = false;		/* false for token */
  ept_entry_n->fields.read_access = false;	  	/** false for token */
  ept_entry_n->fields.write_access = false; 	  /** false for token */

  const auto ept_entry_token =
    EptGetEptPtEntry(processor_data->ept_data_token, pa);
  ept_entry_token->fields.execute_access = false;
  ept_entry_token->fields.read_access = true;
  ept_entry_token->fields.write_access = true;

  RweSetSystemStructsAccessAttribs(pa);

  return true;
}


// Clear access bits for the Default EPT
// Set access bits only for the EPT with isolated driver and clear bits for all other EPTs
_Use_decl_annotations_ static bool RwepFileObjPageCallback(void* va, ULONG64 pa,
  void* context) {
  if (!context) {
    return false;
  }

  if (!pa) {
    UNREFERENCED_PARAMETER(va);
    HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.", va);
    return true;
  }

  const auto processor_data = reinterpret_cast<ProcessorData*>(context);

  const auto ept_entry_n =
    EptGetEptPtEntry(processor_data->ept_data_default_enclave, pa);
  ept_entry_n->fields.execute_access = /*true*/ false;
  ept_entry_n->fields.read_access = /*true*/ false;
  ept_entry_n->fields.write_access = /*true*/ false;

  RweSetFileObjAccessAttribs(va, pa);

  //HYPERPLATFORM_LOG_DEBUG_SAFE("Alloc NORMAL : S:--E D:RWE O:RWE %p", PAGE_ALIGN(va));
  return true;
}

// Clear access bits for the Default EPT
// Set access bits only for the EPT with isolated driver and clear bits for all other EPTs
_Use_decl_annotations_ static bool RwepHandleTablePageCallback(void* va, ULONG64 pa,
  void* context) {
  if (!context) {
    return false;
  }

  if (!pa) {
    UNREFERENCED_PARAMETER(va);
    HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.", va);
    return true;
  }

  const auto processor_data = reinterpret_cast<ProcessorData*>(context);

  const auto ept_entry_n =
    EptGetEptPtEntry(processor_data->ept_data_default_enclave, pa);
  ept_entry_n->fields.execute_access = true; // < We grant access to the entry for the default enclave
  ept_entry_n->fields.read_access = true; // < it helps to prevent too many attempts to the page 
  ept_entry_n->fields.write_access = true; // < with the protected data

  RweSetHandleTableAccessAttribs(va, pa);

  //HYPERPLATFORM_LOG_DEBUG_SAFE("Alloc NORMAL : S:--E D:RWE O:RWE %p", PAGE_ALIGN(va));
  return true;
}

_Use_decl_annotations_ static bool RwepGrantAccessCallback(void* va, ULONG64 pa,
  void* context) {
  if (!context) {
    return false;
  }

  if (!pa) {
    UNREFERENCED_PARAMETER(va);
    HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.", va);
    return true;
  }

  const auto processor_data = reinterpret_cast<ProcessorData*>(context);

  const auto ept_entry_n =
    EptGetEptPtEntry(processor_data->ept_data_default_enclave, pa);
  ept_entry_n->fields.execute_access = true;
  ept_entry_n->fields.read_access = true;
  ept_entry_n->fields.write_access = true;

  // const auto ept_entry_token =
  //   EptGetEptPtEntry(processor_data->ept_data_token, pa);
  // An access to the Token fields is not restricted inside Token Enclave
  // And it does not to be given

  RweSetSystemStructsGrantAttribs(pa);

  return true;
}


// Make source ranges non-executable for normal pages and executable for
// monitor pages
// _Use_decl_annotations_ static bool RwepSrcPageCallback(void* va, ULONG64 pa,
//                                                        void* context) {
//   if (!context) {
//     return false;
//   }
// 
//   if (!pa) {
//     UNREFERENCED_PARAMETER(va);
//     HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.", va);
//     return true;
//   }
// 
//   const auto processor_data = reinterpret_cast<ProcessorData*>(context);
// 
//   const auto ept_entry_n =
//       EptGetEptPtEntry(processor_data->ept_data_default_enclave, pa);
//   ept_entry_n->fields.execute_access = false;
// 
//   const auto ept_entry_m =
//       EptGetEptPtEntry(processor_data->ept_data_monitor, pa);
//   ept_entry_m->fields.execute_access = true;
// 
//   HYPERPLATFORM_LOG_DEBUG_SAFE("NORMAL : S:RW- D:RWE O:RWE %p", PAGE_ALIGN(va));
//   HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RWE D:RW- O:RW- %p", PAGE_ALIGN(va));
//   return true;
// }

// Make dest ranges non-readable/writable/executable for monitor pages
// _Use_decl_annotations_ static bool RwepDstPageCallback(void* va, ULONG64 pa,
//                                                        void* context) {
//   if (!context) {
//     return false;
//   }
// 
//   if (!pa) {
//     UNREFERENCED_PARAMETER(va);
//     HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.", va);
//     return true;
//   }
// 
//   const auto processor_data = reinterpret_cast<ProcessorData*>(context);
//   const auto ept_entry = EptGetEptPtEntry(processor_data->ept_data_monitor, pa);
//   ept_entry->fields.execute_access = false;
//   ept_entry->fields.write_access = false;
//   ept_entry->fields.read_access = false;
//   HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RWE D:--- O:RW- %p", PAGE_ALIGN(va));
//   return true;
// }




// Apply ranges to EPT attributes
_Use_decl_annotations_ void RweVmcallApplyRanges(
    ProcessorData* processor_data) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

  // Make sure no EPT entry is in a temporary state. Hence updating EPT entries
  // do not cause confusion.
  NT_ASSERT(!processor_data->rwe_data->last_data.ept_entry);

  g_rwep_shared_data.os_internal_drivers_range.for_each_page(RwepOSinternalDriversPageCallback,
    processor_data);

  g_rwep_shared_data.isolated_drivers_range.for_each_page(RwepNewlyLoadedDriversPageCallback,
    processor_data);

  g_rwep_shared_data.os_internal_data_range.for_each_page(RwepOSInternalDataPageCallback,
    processor_data);

  g_rwep_shared_data.file_objects_ranges.for_each_page(RwepFileObjPageCallback,
    processor_data);

  g_rwep_shared_data.handle_table_ranges.for_each_page(RwepHandleTablePageCallback,
    processor_data);

  if (g_rwep_shared_data.grant_access_list.size()) {
    g_rwep_shared_data.grant_access_list.for_each_page(RwepGrantAccessCallback,
      processor_data);
    g_rwep_shared_data.grant_access_list.clear();
  }

//   g_rwep_shared_data.src_ranges.for_each_page(RwepSrcPageCallback,
//                                               processor_data);
//   g_rwep_shared_data.dst_ranges.for_each_page(RwepDstPageCallback,
//                                               processor_data);
  UtilInveptGlobal();
}

//////////////////////////////////////////////////////////////////////////

_Use_decl_annotations_ void RweHandleTlbFlush(ProcessorData* processor_data) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

  if (g_rwep_shared_data.v2p_map.refresh(processor_data)) {
    UtilForEachProcessorDpc(RwepApplyRangesDpcRoutine, nullptr);
  }
}

}  // extern "C"
