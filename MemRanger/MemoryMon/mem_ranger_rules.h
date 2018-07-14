
#pragma once

#include <fltKernel.h>
#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#include <vector>
#include "..\shared\allmempro_shared.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "rwe.h"

typedef struct _ALLOCATED_POOL {
	void*				poolStart;
	void*				poolEnd;
}ALLOCATED_POOL, *PALLOCATED_POOL;

typedef struct _ISOLATED_MEM_ENCLOSURE {
	EptData*	ept;
	void*		driverStart;
	void*		driverEnd;
	std::vector<ALLOCATED_POOL> mem_allocated_list;
}ISOLATED_MEM_ENCLOSURE;


using ConstructCallback = EptCommonEntry *(*)(EptCommonEntry *table, ULONG table_level, ULONG64 physical_address,
	EptData *ept_data, bool default_access);


class MemoryRanger {

public:
	
	MemoryRanger() {};
		
	void for_each_ept(_In_ ConstructCallback callback,
		ULONG table_level, ULONG64 physical_address, bool default_access) {
		for (auto & each_driver : protected_memory_list) {
			EptData *ept = each_driver.ept;
			callback(ept->ept_pml4, table_level,
				physical_address, ept, default_access);
		}
	}

	void add_driver(EptData* ept, void* address, SIZE_T size) {
		ISOLATED_MEM_ENCLOSURE mem_enclosure = { 0 };
		const auto end_address =
			reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
		mem_enclosure.ept = ept;
		mem_enclosure.driverStart = address;
		mem_enclosure.driverEnd = end_address;
		protected_memory_list.push_back(mem_enclosure);
	}

	void add_pool(void* driverAddr, void* address, SIZE_T size) {
		for (auto & each_driver : protected_memory_list) {
			if (UtilIsInBounds(driverAddr, each_driver.driverStart, each_driver.driverEnd)) {
				const auto end_address =
					reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
				each_driver.mem_allocated_list.push_back(ALLOCATED_POOL{ address, end_address });
				return;
			}
		}
	}

	EptData* get_drivers_ept(void* driverAddr) {
		for (const auto& each_driver : protected_memory_list) {
			if (UtilIsInBounds(driverAddr, each_driver.driverStart, each_driver.driverEnd)) {
				return each_driver.ept;
				break;
			}
		}
		return nullptr;
	}

	EptData* access_to_the_allocated_data(void* accessAddr) {
		for (const auto& driver : protected_memory_list) {
			for (const auto& memory : driver.mem_allocated_list) {
				if (UtilIsInBounds(accessAddr, memory.poolStart, memory.poolEnd)) {
					return driver.ept;
				}
			}
		}
		return nullptr;
	}

	std::vector<ISOLATED_MEM_ENCLOSURE> protected_memory_list;
}; 