// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements the V2PMap2 class.

#include "V2PMap.h"
#include "rwe.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/vmm.h"

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

/*_Use_decl_annotations_*/ V2PMap2::V2PMap2() {
  KeInitializeSpinLock(&v2p_map_spinlock_);
}

_Use_decl_annotations_ void V2PMap2::add(void* address, SIZE_T size) {
  const auto start_address = reinterpret_cast<ULONG_PTR>(address);
  const auto end_address = start_address + size - 1;

  const auto pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
      start_address, end_address - start_address + 1);
  for (auto page_index = 0ul; page_index < pages; ++page_index) {
    const auto va_base = PAGE_ALIGN(start_address + PAGE_SIZE * page_index);
    const auto pa_base = UtilPaFromVa(va_base);
    v2p_map_.push_back(V2PMapEntry{va_base, pa_base});

   // HYPERPLATFORM_LOG_DEBUG("V2PMap2::add Map: V:%p P:%p", va_base, pa_base);
  }
}

_Use_decl_annotations_ bool V2PMap2::del(const void* address, const SIZE_T size) {
	bool b_res = false;
	HYPERPLATFORM_LOG_DEBUG("V2PMap2::del Map: Virt:%p Size:%x", address, size);
	const auto start_address = reinterpret_cast<ULONG_PTR>(address);
	const auto end_address = start_address + size - 1;

	const auto pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
		start_address, end_address - start_address + 1);
	for (auto page_index = 0ul; page_index < pages; ++page_index) {
		const auto va_base = PAGE_ALIGN(start_address + PAGE_SIZE * page_index);
		const auto pa_base = UtilPaFromVa(va_base);

		for (auto item = v2p_map_.begin(); item != v2p_map_.end(); ++item) {
			if ((va_base == item->va) && (pa_base == item->pa)) {
				v2p_map_.erase(item);
				HYPERPLATFORM_LOG_DEBUG("V2PMap2::+del Map: V:%p P:%p ", va_base, pa_base);
				b_res = true;
				break;
			}
		}
	}
	if (!b_res){
		HYPERPLATFORM_LOG_DEBUG("V2PMap2::-del Map");
	}	
	return b_res;
}



_Use_decl_annotations_ bool V2PMap2::refresh(ProcessorData* processor_data) {
  bool need_refresh = false;

  for (auto& map : v2p_map_) {
    NT_ASSERT(map.va == PAGE_ALIGN(map.va));
    NT_ASSERT(map.pa == reinterpret_cast<ULONG64>(PAGE_ALIGN(map.pa)));
    const auto new_pa = UtilPaFromVa(map.va);
    if (new_pa == map.pa) {
      continue;
    }

    if (map.pa) {
      const auto old_ept_entry_n =
          EptGetEptPtEntry(processor_data->ept_data_default, map.pa);

	  if (RweIsInsideSystemDriversRange(map.va)) {
		  old_ept_entry_n->fields.execute_access = true;
		  old_ept_entry_n->fields.read_access = true;
		  old_ept_entry_n->fields.write_access = true;
	  }
	  else if (RweIsInsideSystemStructsRange(map.va)) {
		  HYPERPLATFORM_COMMON_DBG_BREAK();
		  old_ept_entry_n->fields.execute_access = true;
		  old_ept_entry_n->fields.read_access = true;
		  old_ept_entry_n->fields.write_access = true;
	  }
	  else if (RweIsInsideIsolatedDriversRange(map.va)) {
		  old_ept_entry_n->fields.execute_access = false;
		  old_ept_entry_n->fields.read_access = false;
		  old_ept_entry_n->fields.write_access = false;
	  }
	  else if (RweIsInsideMemoryAllocationRange(map.va)) {
		  old_ept_entry_n->fields.execute_access = false;
		  old_ept_entry_n->fields.read_access = false;
		  old_ept_entry_n->fields.write_access = false;
	  }
	  else if (RweIsInsideHandleTableRange(map.va)) {
		  HYPERPLATFORM_COMMON_DBG_BREAK();
		  old_ept_entry_n->fields.execute_access = false;
		  old_ept_entry_n->fields.read_access = false;
		  old_ept_entry_n->fields.write_access = false;
	  }
	  else {
		  old_ept_entry_n->fields.execute_access = true;
		  old_ept_entry_n->fields.read_access = true;
		  old_ept_entry_n->fields.write_access = true;
	  }

	/*token*/  const auto token_ept_entry_n =
		  EptGetEptPtEntry(processor_data->ept_data_token, map.pa);

	  if (RweIsInsideSystemDriversRange(map.va)) {
		  token_ept_entry_n->fields.execute_access = true;
		  token_ept_entry_n->fields.read_access = true;
		  token_ept_entry_n->fields.write_access = true;
	  }
	  else if (RweIsInsideSystemStructsRange(map.va)) {
		  HYPERPLATFORM_COMMON_DBG_BREAK();
		  token_ept_entry_n->fields.execute_access = true;
		  token_ept_entry_n->fields.read_access = true;
		  token_ept_entry_n->fields.write_access = true;
	  }
	  else if (RweIsInsideIsolatedDriversRange(map.va)) {
		  token_ept_entry_n->fields.execute_access = false;
		  token_ept_entry_n->fields.read_access = false;
		  token_ept_entry_n->fields.write_access = false;
	  }
	  else if (RweIsInsideMemoryAllocationRange(map.va)) {
		  token_ept_entry_n->fields.execute_access = false;
		  token_ept_entry_n->fields.read_access = false;
		  token_ept_entry_n->fields.write_access = false;
	  }
	  else if (RweIsInsideHandleTableRange(map.va)) {
		  HYPERPLATFORM_COMMON_DBG_BREAK();
		  token_ept_entry_n->fields.execute_access = false;
		  token_ept_entry_n->fields.read_access = false;
		  token_ept_entry_n->fields.write_access = false;
	  }
	  else {
		  token_ept_entry_n->fields.execute_access = true;
		  token_ept_entry_n->fields.read_access = true;
		  token_ept_entry_n->fields.write_access = true;
	  }


	  RweRefreshTables(map.pa, map.va);

    }

//     HYPERPLATFORM_LOG_DEBUG_SAFE("V2PMap2::refresh Map: V:%p P:%p => %p", map.va, map.pa,
//                                  new_pa);
    map.pa = new_pa;
    need_refresh = true;
  }
  return need_refresh;
}
