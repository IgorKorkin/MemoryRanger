
#include "active_mem_protector.h"

/*  */
void ProtectedDrivers::add(const PROTECTED_DRIVER & one_driver) {
	protected_drivers.push_back(one_driver);
}

bool ProtectedDrivers::is_it_from_protected_drv(const _In_ void* src_address) {
	bool b_res = false;
	
	if (protected_drivers.size()) {
		
		// 1. we check who is trying to access to this memory
		// Should we add a new memory access rule or not
		for (std::vector<PROTECTED_DRIVER>::iterator 
			it = protected_drivers.begin(); it != protected_drivers.end(); it++) {
			if ((it->drvStartAddr <= src_address) && 
				(((char*)src_address <= ((char*)it->drvStartAddr + it->drvSize)))) {
				// The driver who has allocated this memory tries to access it
				// YEP we need to add a rule
				b_res = true;
				break;
			}
		}// for ()
		
	}	
	return b_res;
}

//////////////////////////////////////////////////////////////////////////

void ActiveMemoryProtector::add(const MEMORY_ACCESS_RULE & memory_access_rule) {
	list_of_mem_rules.push_back(memory_access_rule);
}

NTSTATUS ActiveMemoryProtector::get_list_of_memory_access_rules(MEMORY_ACCESS_RULE *mem_rules, ULONG & mem_rules_sz)
{
	NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

	if (list_of_mem_rules.empty()){
		mem_rules_sz = 0;
		nt_status = STATUS_SUCCESS;
	}
	else if (mem_rules_sz < (ULONG)list_of_mem_rules.size() * sizeof MEMORY_ACCESS_RULE) {
		mem_rules_sz = (ULONG)list_of_mem_rules.size() * sizeof MEMORY_ACCESS_RULE;
		nt_status = STATUS_BUFFER_OVERFLOW;
	}
	else if (mem_rules){
		MEMORY_ACCESS_RULE *current = mem_rules;
		for (std::vector<MEMORY_ACCESS_RULE>::iterator it = list_of_mem_rules.begin();
		it != list_of_mem_rules.end(); it++) {
			current->drvStartAddr = it->drvStartAddr;
			current->drvSize = it->drvSize;
			current->allocStartAddr = it->allocStartAddr;
			current->allocSize = it->allocSize;
			current++;
		}
		nt_status = STATUS_SUCCESS;
	}

	if (list_of_mem_rules.size()){
		HYPERPLATFORM_LOG_INFO_SAFE("[POLICY] Active Data Protection [BEGIN] \r\n");
		for (std::vector<MEMORY_ACCESS_RULE>::iterator it = list_of_mem_rules.begin();
			it != list_of_mem_rules.end(); it++) {
			HYPERPLATFORM_LOG_INFO_SAFE(" Driver %I64X-%I64X has allocated memory %I64X-%I64X \r\n",
				it->drvStartAddr,
				it->drvSize,
				it->allocStartAddr,
				it->allocSize);
		}
		HYPERPLATFORM_LOG_INFO_SAFE("[POLICY] Active Data Protection [END] \r\n");
	}
	else {
		HYPERPLATFORM_LOG_INFO_SAFE("[POLICY] Active Data Protection list is empty \r\n");
	}
	
	return nt_status;
}

bool ActiveMemoryProtector::is_it_illegal_access(const _In_ void* src_address, const _In_ void* dst_address) {
	bool b_res = false;
	KeWaitForMutexObject(&MemProtectorMutex, Executive, KernelMode, FALSE, NULL);
	if (list_of_mem_rules.size()) {
		// 1. Should we hide this dst_address ? 
		for (std::vector<MEMORY_ACCESS_RULE>::iterator it = list_of_mem_rules.begin(); it != list_of_mem_rules.end(); it++) {
			if ((it->allocStartAddr <= dst_address) && (((char*)dst_address <= ((char*)it->allocStartAddr + it->allocSize)))) {
				// 2. Yes. now we check who is trying to access to this memory
				//    Something wrong might happen if this access is unauthorized
				b_res = true;
				if ((it->drvStartAddr <= src_address) && (((char*)src_address <= ((char*)it->drvStartAddr + it->drvSize)))) {
					// 3. Everything is OK. The driver who has allocated this memory tries to access it
					b_res = false;
					break;
				}
			}
		}// for ()

		if (b_res == true) {
			// It means that unauthorized code tries to access the protected data
			;
		}
	}
	KeReleaseMutex(&MemProtectorMutex, FALSE);
	return b_res;

}