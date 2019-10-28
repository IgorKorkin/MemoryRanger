// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements the AddressRanges class.

#include "AddressRanges.h"
#include "../HyperPlatform/common.h"
#include "../HyperPlatform/log.h"
#include "../HyperPlatform/util.h"

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

/*_Use_decl_annotations_*/ AddressRanges::AddressRanges() {
  KeInitializeSpinLock(&ranges_spinlock_);
}

_Use_decl_annotations_ void AddressRanges::add(void* address, SIZE_T size) {
  ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  if (size < PAGE_SIZE){
      if (MmIsAddressValid(address)) {
          const auto end_address =
              reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
          ranges_.push_back(AddressRangeEntry{ address, end_address });
      }
  }
  else if (size % PAGE_SIZE == 0) {
    NT_ASSERT(address == PAGE_ALIGN(address));

    const auto start_address = reinterpret_cast<ULONG_PTR>(address);
    const auto end_address = start_address + size - 1;

    const auto pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
        start_address, end_address - start_address + 1);
    for (auto page_index = 0ul; page_index < pages; ++page_index) {
      const auto va_base = PAGE_ALIGN(start_address + PAGE_SIZE * page_index);
      if (MmIsAddressValid(va_base)) {
        bool is_access_ok = false;
        __try { *(char*)va_base;   is_access_ok = true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { is_access_ok = false; }
        if (is_access_ok) {
            const auto page_end =
                reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(va_base) + PAGE_SIZE - 1);
            ranges_.push_back(AddressRangeEntry{ va_base, page_end });
        }
      }
    }
  }
}

_Use_decl_annotations_ bool AddressRanges::del(const void* address, const SIZE_T size) {
  
  if (size < PAGE_SIZE) {
    const auto end_address =
      reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
    for (auto item = ranges_.begin(); item != ranges_.end(); ++item) {
      if ((address == item->start_address) && (end_address == item->end_address)) {
        ranges_.erase(item);
        return true;
      }
    }
  }
  else if (size % PAGE_SIZE == 0) {
    NT_ASSERT(address == PAGE_ALIGN(address));

    auto b_res = false;
    const auto start_address = reinterpret_cast<ULONG_PTR>(address);
    const auto end_address = start_address + size - 1;
    
    const auto pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
      start_address, end_address - start_address + 1);
    for (auto page_index = 0ul; page_index < pages; ++page_index) {
      const auto page_address = PAGE_ALIGN(start_address + PAGE_SIZE * page_index);
      const auto page_end =
        reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(page_address) + PAGE_SIZE - 1);

      for (auto item = ranges_.begin(); item != ranges_.end(); ++item) {
        if ((page_address == item->start_address) && (page_end == item->end_address)) {
          ranges_.erase(item);
          b_res = true;
        }
      }
    }
    return b_res;
  }
  return false;
}


_Use_decl_annotations_ bool AddressRanges::is_in_range(void* address) const {
  bool inside = false;
  for (const auto& range : ranges_) {
    if (UtilIsInBounds(address, range.start_address, range.end_address)) {
      inside = true;
      break;
    }
  }
  return inside;
}

_Use_decl_annotations_ bool AddressRanges::is_in_range_page_align(void* address) const {
  bool inside = false;
  for (const auto& range : ranges_) {
    if (UtilIsInBounds(PAGE_ALIGN(address), PAGE_ALIGN(range.start_address), PAGE_ALIGN(range.end_address))) {
      inside = true;
      break;
    }
  }
  return inside;
}

_Use_decl_annotations_ void AddressRanges::for_each_page(
    ForEachCallback callback, void* context) {
  for (const auto& range : ranges_) {
    const auto start_address = reinterpret_cast<ULONG_PTR>(range.start_address);
    const auto end_address = reinterpret_cast<ULONG_PTR>(range.end_address);
    const auto num_of_pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
        start_address, end_address - start_address + 1);
    for (auto page_index = 0ul; page_index < num_of_pages; ++page_index) {
      const auto va =
          reinterpret_cast<void*>(start_address + PAGE_SIZE * page_index);
      const auto pa = UtilPaFromVa(va);
      if (!callback(va, pa, context)) {
        break;
      }
    }
  }
}
