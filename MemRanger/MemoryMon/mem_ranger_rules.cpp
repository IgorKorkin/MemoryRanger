#include "mem_ranger_rules.h"

void MemoryRanger::for_each_ept(_In_ ConstructCallback callback,
  ULONG table_level, ULONG64 physical_address, bool default_access) {
  for (auto & each_driver : protected_memory_list) {
    EptData *ept = each_driver.ept;
    callback(ept->ept_pml4, table_level,
      physical_address, ept, default_access);
  }
}

void MemoryRanger::add_driver_enclave(EptData* ept, void* address, SIZE_T size) {
  ISOLATED_MEM_ENCLAVE mem_enclosure = { 0 };
  const auto end_address =
    reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  mem_enclosure.ept = ept;
  mem_enclosure.driverStart = address;
  mem_enclosure.driverEnd = end_address;
  protected_memory_list.push_back(mem_enclosure);
}

bool MemoryRanger::add_pool(void* driverAddr, void* address, SIZE_T size) {
  for (auto & each_driver : protected_memory_list) {
    if (UtilIsInBounds(driverAddr, each_driver.driverStart, each_driver.driverEnd)) {
      const auto end_address =
        reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
      each_driver.mem_allocated_list.push_back(ALLOCATED_POOL{ address, end_address });
      return true;
    }
  }
  return false;
}

SIZE_T MemoryRanger::del_pool(void* driverAddress, void* allocAddr) {
  SIZE_T size = 0;
  for (auto & each_driver : protected_memory_list) {
    if (UtilIsInBounds(driverAddress, each_driver.driverStart, each_driver.driverEnd)) {
      for (auto pool = each_driver.mem_allocated_list.begin();
        pool != each_driver.mem_allocated_list.end(); ++pool) {
        if (allocAddr == pool->startAddr) {
          void* end_addr = pool->endAddr;
          size =
            reinterpret_cast<SIZE_T>(reinterpret_cast<void*>((reinterpret_cast<ULONG_PTR>(end_addr) -
              reinterpret_cast<ULONG_PTR>(allocAddr) + 1)));
          each_driver.mem_allocated_list.erase(pool);
          return size;
        }
      }
    }
  }
  return size;
}

EptData* MemoryRanger::access_to_the_allocated_data(void* accessAddr) {
  for (const auto& driver : protected_memory_list) {
    for (const auto& memory : driver.mem_allocated_list) {
      if (UtilIsInBounds(accessAddr, memory.startAddr, memory.endAddr)) {
        return driver.ept;
      }
    }
  }
  return nullptr;
}

//////////////////////////////////////////////////////////////////////////

bool MemoryRanger::add_handle_entry(void* driverAddr, void* address, SIZE_T size) {
  for (auto & each_driver : protected_memory_list) {
    if (UtilIsInBounds(driverAddr, each_driver.driverStart, each_driver.driverEnd)) {
      const auto end_address =
        reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
      each_driver.handle_entry_list.push_back(PROTECTED_MEM{ address, end_address });
      return true;
    }
  }
  return false;
}

bool MemoryRanger::two_handle_entries_at_one_page(void* handleEntry) {
  int handle_entries_at_one_page = 0;
  for (auto & each_driver : protected_memory_list) {
    for (const auto & each_handle_entry : each_driver.handle_entry_list) {
      if (UtilIsInBounds(PAGE_ALIGN(handleEntry), PAGE_ALIGN(each_handle_entry.startAddr), PAGE_ALIGN(each_handle_entry.endAddr))) {
        handle_entries_at_one_page++;
      }
    }
  }
  return (handle_entries_at_one_page >= 2);
}

SIZE_T MemoryRanger::del_handle_entry(void* driverAddress, void* startHandleEntry) {
  SIZE_T size = 0;
  for (auto & each_driver : protected_memory_list) {
    if (UtilIsInBounds(driverAddress, each_driver.driverStart, each_driver.driverEnd)) {
      for (auto each_handle_entry = each_driver.handle_entry_list.begin();
        each_handle_entry != each_driver.handle_entry_list.end(); ++each_handle_entry) {
        if (startHandleEntry == each_handle_entry->startAddr) {
          void* end_addr = each_handle_entry->endAddr;
          size =
            reinterpret_cast<SIZE_T>(reinterpret_cast<void*>((reinterpret_cast<ULONG_PTR>(end_addr) -
              reinterpret_cast<ULONG_PTR>(startHandleEntry) + 1)));
          each_driver.handle_entry_list.erase(each_handle_entry);
          return size;
        }
      }
    }
  }
  return size;
}

//////////////////////////////////////////////////////////////////////////

bool MemoryRanger::add_file_object(void* driverAddr, void* address, SIZE_T size) {
  for (auto & each_driver : protected_memory_list) {
    if (UtilIsInBounds(driverAddr, each_driver.driverStart, each_driver.driverEnd)) {
      const auto end_address =
        reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
      each_driver.file_objects_list.push_back(FILEOBJECT{ address, end_address });
      return true;
    }
  }
  return false;
}

SIZE_T MemoryRanger::del_file_object(void* driverAddress, void* startFileObj) {
  SIZE_T size = 0;
  for (auto & each_driver : protected_memory_list) {
    if (UtilIsInBounds(driverAddress, each_driver.driverStart, each_driver.driverEnd)) {
      for (auto each_fileobj = each_driver.file_objects_list.begin();
        each_fileobj != each_driver.file_objects_list.end(); ++each_fileobj) {
        if (startFileObj == each_fileobj->startAddr) {
          void* end_addr = each_fileobj->endAddr;
          size =
            reinterpret_cast<SIZE_T>(reinterpret_cast<void*>((reinterpret_cast<ULONG_PTR>(end_addr) -
              reinterpret_cast<ULONG_PTR>(startFileObj) + 1)));
          each_driver.file_objects_list.erase(each_fileobj);
          return size;
        }
      }
    }
  }
  return size;
}

EptData* MemoryRanger::access_to_the_file_object(void* accessAddr) {
  for (const auto& each_driver : protected_memory_list) {
    for (const auto& each_fileobj : each_driver.file_objects_list) {
      if (UtilIsInBounds(accessAddr, each_fileobj.startAddr, each_fileobj.endAddr)) {
        return each_driver.ept;
      }
    }
  }
  return nullptr;
}

EptData* MemoryRanger::access_to_the_handle_table(void* accessAddr) {
  for (const auto& each_driver : protected_memory_list) {
    for (const auto& each_handle_entry : each_driver.handle_entry_list) {
      if (UtilIsInBounds(accessAddr, each_handle_entry.startAddr, each_handle_entry.endAddr)) {
        return each_driver.ept;
      }
    }
  }
  return nullptr;
}

//////////////////////////////////////////////////////////////////////////

EptData* MemoryRanger::get_drivers_ept(void* driverAddr) {
  for (const auto& each_driver : protected_memory_list) {
    if (UtilIsInBounds(driverAddr, each_driver.driverStart, each_driver.driverEnd)) {
      return each_driver.ept;
      break;
    }
  }
  return nullptr;
}

