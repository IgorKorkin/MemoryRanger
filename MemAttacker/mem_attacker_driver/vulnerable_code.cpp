#include "vulnerable_code.h"
#include <intrin.h>

namespace vulnerable_code {

	/************************************************************************/
	/*  The first one is the stack overflow vulnerability                    */
	/************************************************************************/

	NTSTATUS stack_overflow_stub(IN PVOID UserBuffer, IN SIZE_T Size) {
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		DbgPrint(">> run_stack_overflow \r\n");
		
		UINT64 CR4_value= __readcr4();
		const int SMEP_bit = 20;
		CR4_value &= ~(1UL << SMEP_bit);
		__writecr4(CR4_value);

		status = run_stack_overflow(UserBuffer, Size);

		DbgPrint("<< run_stack_overflow \r\n");

		return status;
	}

	NTSTATUS run_stack_overflow(IN PVOID UserBuffer, IN SIZE_T Size) {
		ULONG KernelBuffer[BUFFER_SIZE] = { 0 }; /* sizeof = 0x800 bytes or   4 bytes * 512 entries   */

		RtlCopyMemory((PVOID)KernelBuffer, UserBuffer, Size);

		return STATUS_SUCCESS;
	}

	/************************************************************************/
	/*   The second one is the use-after-free (UAF) vulnerability                 */
	/************************************************************************/

	PBUFFER_FUNC g_OneObject = NULL;

	VOID null_callback_func() {
		PAGED_CODE();
		DbgPrint("[+] Use After Free Object Callback\n");
	}

	#define _STRINGIFY(value) #value
	#define STRINGIFY(value) _STRINGIFY(value)

	NTSTATUS uaf_allocate_object() {
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		// Allocate one object
		__try {
			PBUFFER_FUNC one_buffer_chunk =
				(PBUFFER_FUNC)ExAllocatePoolWithTag(NonPagedPool, sizeof(BUFFER_FUNC), g_ObjectTag);
			if (one_buffer_chunk) {
				DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(g_ObjectTag));
				DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
				DbgPrint("[+] Pool Size: 0x%X\n", sizeof(BUFFER_FUNC));
				DbgPrint("[+] Pool Chunk: 0x%p\n", one_buffer_chunk);

				const char byte_sym = /*0x49*/ (int)'I';
				RtlFillMemory((PVOID)one_buffer_chunk->object.buffer,
					sizeof(one_buffer_chunk->object.buffer), byte_sym);

				// Null terminate the char buffer
				one_buffer_chunk->object.buffer[sizeof(one_buffer_chunk->object.buffer) - 1] = '\0';

				// Set the object Callback function
				one_buffer_chunk->callback_func = &null_callback_func;

				// Assign the address of UseAfterFree to a global variable
				g_OneObject = one_buffer_chunk;

				nt_status = STATUS_SUCCESS;
			}
			else{
				DbgPrint("[-] Unable to allocate a Pool chunk\n");
				nt_status = STATUS_NO_MEMORY; // nt_status = GetExceptionCode();
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			nt_status = GetExceptionCode();
			DbgPrint("[-] Exception Code: 0x%X\n", nt_status);
		}
		return nt_status;
	}

	NTSTATUS uaf_allocate_object_stub() {
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		nt_status = uaf_allocate_object();

		return nt_status;
	}


	NTSTATUS uaf_free_object() {
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		__try {
			if (g_OneObject) {
				DbgPrint("[+] Freeing UaF Object\n");
				DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(g_ObjectTag));
				DbgPrint("[+] Pool Chunk: 0x%p\n", g_OneObject);
				ExFreePoolWithTag((PVOID)g_OneObject, g_ObjectTag);
				nt_status = STATUS_SUCCESS;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			nt_status = GetExceptionCode();
			DbgPrint("[-] Exception Code: 0x%X\n", nt_status);
		}
		return nt_status;
	}

	NTSTATUS uaf_free_object_stub() {
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		nt_status = uaf_free_object();

		return nt_status;
	}

	NTSTATUS uaf_use_object() {
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		static auto counts = 0;
		if (g_OneObject) {
			DbgPrint(" kernel-mode attempt # %d \n", ++counts);
			DbgPrint("[+] Using UaF Object\n");
			DbgPrint("[+] g_OneObject: 0x%p\n", g_OneObject);
			DbgPrint("[+] g_OneObject->Callback: 0x%p\n", g_OneObject->callback_func);
			DbgPrint("[+] Calling Callback\n");
			// BugCheck - SYSTEM_SERVICE_EXCEPTION (3b)
			// EXCEPTION_CODE: (NTSTATUS) 0xc0000005
			if (g_OneObject->callback_func) {
				g_OneObject->callback_func();
			}
			nt_status = STATUS_SUCCESS;
		}

		return nt_status;
	}

	NTSTATUS uaf_use_object_stub() {
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		nt_status = uaf_use_object();

		return nt_status;
	}

	NTSTATUS uaf_allocate_fake(PBUFFER_OBJECT pFakeUserBuf) {
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		PBUFFER_OBJECT fake_chunk =
			(PBUFFER_OBJECT)ExAllocatePoolWithTag(NonPagedPool, sizeof(BUFFER_OBJECT), g_ObjectTag);
		if (fake_chunk) {
// 			DbgPrint("[+] Fake Pool Tag: %s\n", STRINGIFY(g_ObjectTag));
// 			DbgPrint("[+] Fake Pool Type: %s\n", STRINGIFY(NonPagedPool));
// 			DbgPrint("[+] Fake Pool Size: 0x%X\n", sizeof(BUFFER_OBJECT));
// 			DbgPrint("[+] Fake Pool Chunk: 0x%p\n", fake_chunk);
			// Drivers must call ProbeForRead inside a try/except block.
			__try {
				// Kernel-mode drivers must use ProbeForRead to validate read access to buffers that are allocated in user space.
				ProbeForRead((PVOID)pFakeUserBuf, sizeof(BUFFER_OBJECT), (ULONG)__alignof(BUFFER_OBJECT));
				nt_status = STATUS_SUCCESS;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				nt_status = GetExceptionCode();
				DbgPrint("[-] Exception Code: 0x%X\n", nt_status);
			}
			if (NT_SUCCESS(nt_status)){
				// Copy the user's Fake structure to the kernel Pool chunk
				RtlCopyMemory((PVOID)fake_chunk, (PVOID)pFakeUserBuf, sizeof(BUFFER_OBJECT));

				// Null terminate the char buffer
				fake_chunk->buffer[sizeof(fake_chunk->buffer) - 1] = '\0'; // = 0
//				DbgPrint("[+] Fake Object: 0x%p\n", fake_chunk);
			}
		}
		return nt_status;
	}

	NTSTATUS uaf_allocate_fake_stub(void* pFakeUserBuf) {
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		nt_status = uaf_allocate_fake((PBUFFER_OBJECT)pFakeUserBuf);

		return nt_status;
	}

	/************************************************************************/
	/* The 3rd one is Pool overflow                                         */
	/************************************************************************/

	NTSTATUS pool_overflow_stub(IN PVOID UserBuffer, IN SIZE_T Size) {
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		DbgPrint(">> run_stack_overflow \r\n");

		status = run_pool_overflow(UserBuffer, Size);

		DbgPrint("<< run_stack_overflow \r\n");

		return status;
	}

	NTSTATUS run_pool_overflow(IN PVOID UserBuffer, IN SIZE_T Size) {
		PVOID pKernelBuffer = NULL;
		ULONG Tag = 0x55667744;

		if (NULL != (pKernelBuffer = ExAllocatePoolWithTag(NonPagedPool, BUFFER_SIZE, Tag))) {
			RtlCopyMemory(pKernelBuffer, UserBuffer, Size);
			ExFreePoolWithTag(pKernelBuffer, Tag);
			pKernelBuffer = NULL;
		}

		return STATUS_SUCCESS;
	}

}