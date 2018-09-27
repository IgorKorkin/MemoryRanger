/************************************************************************/
/*                                                                      */
/************************************************************************/


#ifndef ACTIVE_MEM_PROTECTOR_H_
#define ACTIVE_MEM_PROTECTOR_H_

#include <fltKernel.h>
#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#include <vector>
#include "..\shared\allmempro_shared.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"

class ActiveMemoryProtector {

public:
	/*  */
	ActiveMemoryProtector::ActiveMemoryProtector() {
		KeInitializeMutex(&MemProtectorMutex, NULL);
	}

	/*  */
	void add(const MEMORY_ACCESS_RULE & memory_access_rule);

	/*  */
	NTSTATUS get_list_of_memory_access_rules(MEMORY_ACCESS_RULE *out_buf, ULONG & out_buf_sz);
	
	/*  */
	bool is_it_illegal_access(const _In_ void* src_address, const _In_ void* dst_address);

private:
	KMUTEX MemProtectorMutex = { 0 };
	std::vector<MEMORY_ACCESS_RULE> list_of_mem_rules;
};


typedef struct _PROTECTED_DRIVER {
	void*				drvStartAddr;
	unsigned __int64	drvSize;
}PROTECTED_DRIVER, *PPROTECTED_DRIVER;

class ProtectedDrivers {

public:
	/*  */
	ProtectedDrivers::ProtectedDrivers() {
		KeInitializeMutex(&RegDrvMutex, NULL);
	}

	/*  */
	void add(const PROTECTED_DRIVER & one_driver);

	/**/
	bool is_it_from_protected_drv(const _In_ void* src_address);

private:
	KMUTEX RegDrvMutex = { 0 };
	std::vector<PROTECTED_DRIVER> protected_drivers;
};

//////////////////////////////////////////////////////////////////////////

typedef struct _EPROCESS_FIELD {
	void* start_addr;
	int	size;
}EPROCESS_FIELD;

typedef struct _EPROCESS_PID {
	HANDLE ProcessId;
	std::vector<_EPROCESS_FIELD> mem_allocated_list;
}EPROCESS_PID;

using AddOneStructCallback = void (*)(void* address, SIZE_T size);

using DelOneStructCallback = void(*)(void* address, SIZE_T size);

class EprocessStructs {
	public:
		void add(const EPROCESS_PID &proc, AddOneStructCallback callback) {
			protected_eprocess_structs.push_back(proc);
			for (auto const & item : proc.mem_allocated_list) {
				callback(item.start_addr, item.size);
			}
		}

		bool del(const HANDLE ProcessId, DelOneStructCallback callback) {
			if (protected_eprocess_structs.size()) {
				std::vector<EPROCESS_PID>::iterator eproc;
				for (eproc = protected_eprocess_structs.begin(); eproc != protected_eprocess_structs.end(); ++eproc) {
					if (ProcessId == eproc->ProcessId) {
						HYPERPLATFORM_COMMON_DBG_BREAK();
						HYPERPLATFORM_LOG_INFO_SAFE("The EPROCESS %d (0x%x) is going to be deleted",
							ProcessId, ProcessId);
						for (auto const eproc_mem : eproc->mem_allocated_list) {
							callback(eproc_mem.start_addr, eproc_mem.size);
						}
						protected_eprocess_structs.erase(eproc);
						return true;
					}
				}
			}
			return false;
		}

private:
	std::vector<EPROCESS_PID> protected_eprocess_structs;
};



#endif // ACTIVE_MEM_PROTECTOR_H_