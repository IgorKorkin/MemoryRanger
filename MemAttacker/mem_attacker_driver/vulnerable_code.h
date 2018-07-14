#pragma once

#include "mem_attacker_driver.h"

namespace vulnerable_code {

	/*		This function is used to return control to DriverpDeviceControl()
	Because stack overflow overwrites return address in function run_stack_overflow()		*/
	NTSTATUS stack_overflow_stub(IN PVOID UserBuffer, IN SIZE_T Size);

	/* Run vulnerable function with memcpy() */
	NTSTATUS run_stack_overflow(IN PVOID UserBuffer, IN SIZE_T Size);

	const int g_ObjectTag = 'sTyM';

	const int g_Objectsz = 0x54;
	typedef struct _BUFFER_OBJECT {
		char buffer[g_Objectsz];
	} BUFFER_OBJECT, *PBUFFER_OBJECT;

	typedef void(*FunctionPointer)();
	typedef struct _BUFFER_FUNC {
		FunctionPointer callback_func; // it must be always in the first place
		BUFFER_OBJECT object;
	} BUFFER_FUNC, *PBUFFER_FUNC;
	
	NTSTATUS uaf_allocate_object_stub();
	
	NTSTATUS uaf_free_object_stub();
	
	NTSTATUS uaf_use_object_stub();
	
	NTSTATUS uaf_allocate_fake_stub(void* userBuf);

	/* Vulnerable function with pool overflow */
	NTSTATUS pool_overflow_stub(IN PVOID UserBuffer, IN SIZE_T Size);

	NTSTATUS run_pool_overflow(IN PVOID UserBuffer, IN SIZE_T Size);

}