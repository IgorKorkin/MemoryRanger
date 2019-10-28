// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to RWE functions.

#ifndef MEMORYMON_RWE_H_
#define MEMORYMON_RWE_H_

#include "../HyperPlatform/ept.h"

#include <fltKernel.h>

#include "active_mem_protector.h" // < EPROCESS_PID


extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const auto kRwePoolBigPageTableSizeAddress =
    reinterpret_cast<void*>(0xfffff8054462ec28 /*0xfffff80002c66a38*/);

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct ProcessorData;

struct RweData;

#if defined(_AMD64_)
using GpRegisters = struct GpRegistersX64;
#else
using GpRegisters = struct GpRegistersX86;
#endif

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) RweData* RweAllocData();

_IRQL_requires_max_(PASSIVE_LEVEL) void RweFreeData(_In_ RweData* rwe_data);

//////////////////////////////////////////////////////////////////////////

bool ShEnablePageShadowingForNewEnclave(EptData* new_ept);

EptData* RweAllocateNewEnclave();

EptData* RweAddIsolatedEnclave(_In_ void* address, _In_ SIZE_T size);

typedef EptCommonEntry*(TConstructCallback)(
  EptCommonEntry *table, ULONG table_level, ULONG64 physical_address,
  EptData *ept_data, bool default_access);



void RweConstructTablesForEnclaves(_In_ TConstructCallback callback,
  ULONG table_level, ULONG64 physical_address, bool default_access);

void RweAddSrcRange(_In_ void* address, _In_ SIZE_T size);

void RweAddDstRange(_In_ void* address, _In_ SIZE_T size);

void RweAddOneOSInternalDriverRange(void* address, SIZE_T size);

void RweAddOneOSInternalDataRange(void* address, SIZE_T size);

void RweAddEprocess(const EPROCESS_PID & proc);

void RweAddFileObjRange(void* address, SIZE_T size);

void RweAddHandleEntryRange(void* address, SIZE_T size);

bool RweAddHandleTableEntryForNewlyLoadedDriver(void* driverAddr, void* handleTableEntry);

//////////////////////////////////////////////////////////////////////////
void RweDelOneOSInternalDataRange(void* address, SIZE_T size);

bool RweDelEprocess(const HANDLE ProcessId);

bool RweDelFileObject(void* driverAddress, void* fileobjAddr);

bool RweDelHandleTableEntry(void* driverAddress, void* handleEntry);

//////////////////////////////////////////////////////////////////////////
bool RweIsInsideSrcRange(_In_ void* address);

bool RweIsInsideDstRange(_In_ void* address);

bool RweIsInsideOSInternalDriversRange(void* address);

/* Protected drivers range by MemoryRanger */
bool RweIsInsideNewlyLoadedDriversRange(_In_ void* address);

bool RweIsInsideNewlyLoadedDriversRangePageAlign(void* address);

bool RweIsInsideOSInternalDataRange(void* address);

bool RweIsInsideOSInternalDataRangePageAlign(void* address);

bool RweIsInsideFileObjectsRange(void* address);

bool RweIsInsideFileObjectsRangePageAlign(void* address);

bool RweIsInsideHandleTableRange(void* address);

bool RweIsInsideHandleTableRangePageAlign(void* address);

void RweRefreshTables(ProcessorData* processor_data, ULONG64 physical_address, void* virtual_address);

//////////////////////////////////////////////////////////////////////////

_IRQL_requires_max_(PASSIVE_LEVEL) void RweSetDefaultEptAttributes(
    _Inout_ ProcessorData* processor_data);

_IRQL_requires_max_(PASSIVE_LEVEL) void RweSetDefaultEptAttributesForEpt(
  _Inout_ EptData *ept_data);

_IRQL_requires_max_(PASSIVE_LEVEL) void RweApplyRanges();

_IRQL_requires_min_(DISPATCH_LEVEL) void RweHandleNewDeviceMemoryAccess(
    _In_ ULONG64 pa, _In_ void* va);

_IRQL_requires_min_(DISPATCH_LEVEL) void RweHandleEptViolation(
    _Inout_ ProcessorData* processor_data, _In_ void* guest_ip,
    _In_ void* fault_va, _In_ bool read_violation, _In_ bool write_violation,
    _In_ bool execute_violation);

_IRQL_requires_min_(DISPATCH_LEVEL) void RweHandleMonitorTrapFlag(
    _Inout_ ProcessorData* processor_data, _In_ GpRegisters* gp_regs);

_IRQL_requires_min_(DISPATCH_LEVEL) void RweVmcallApplyRanges(
    _Inout_ ProcessorData* processor_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void RweHandleTlbFlush(
    _Inout_ ProcessorData* processor_data);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

extern void* g_rwe_zero_page;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

#endif  // MEMORYMON_RWE_H_
