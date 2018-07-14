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




#endif // ACTIVE_MEM_PROTECTOR_H_