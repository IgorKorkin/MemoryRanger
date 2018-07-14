// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to RWE functions.

#ifndef __RWE_H_
#define __RWE_H_

#include <fltKernel.h>
#include "..\..\HyperPlatform\HyperPlatform\ept.h"
#include "active_mem_protector.h"
#include "mem_ranger_rules.h"

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
    reinterpret_cast<void*>(0xfffff80002c66a38);

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

void RweConstructTables(_In_ ConstructCallback callback,
	ULONG table_level, ULONG64 physical_address, bool default_access);

void RweRefreshTables(ULONG64 physical_address, void* virtual_address);

/*  */
void set_delta_to_cheat_tsc(ULONG64 delta);


/*  */
void RweAddProtectedDriver(void* drv_base, SIZE_T drv_size);

/*  */
void RweAddMemoryAccessRule(const MEMORY_ACCESS_RULE & memory_access_rule);

/*  */
NTSTATUS RweGetMemoryAccessRules(MEMORY_ACCESS_RULE *out_buf, ULONG & out_buf_sz);

/*  */
bool RweShouldWeProtectItbyRules(const _In_ void* src_address, const _In_ void* dst_address);

/*  */
bool RweShouldWeAddMemoryAccessRule(const _In_ void* src_address);

void RweAddAllocatedPool(void* driverAddr, void* poolStart, SIZE_T poolSize);

_IRQL_requires_max_(PASSIVE_LEVEL) RweData* RweAllocData();

_IRQL_requires_max_(PASSIVE_LEVEL) void RweFreeData(_In_ RweData* rwe_data);

void RweAddAllocRange(void* address, SIZE_T size);

void RweAddSystemDrvRange(_In_ void* address, _In_ SIZE_T size);

void RweAddProtectedDrvRange(_In_ void* address, _In_ SIZE_T size);

void RweAddSrcRange(_In_ void* address, _In_ SIZE_T size);

void RweAddDstRange(_In_ void* address, _In_ SIZE_T size);


/* check if 'address' belongs to the pages with the protected region */
bool RweIsInsideMemoryAllocationRangePageAlign(void* address);

/* Precisely check if 'address' belongs to the protected region */
bool RweIsInsideMemoryAllocationRange(_In_ void* address);

/* Protected drivers range by MemoryRanger using page align*/
bool RweIsInsideProtectedDriversRangePageAlign(_In_ void* address);

/* Protected drivers range by MemoryRanger */
bool RweIsInsideProtectedDriversRange(_In_ void* address);

bool RweIsInsideSystemDriversRange(_In_ void* address);

bool RweIsInsideSrcRange(_In_ void* address);

bool RweIsInsideDstRange(_In_ void* address);

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

#endif // __RWE_H_