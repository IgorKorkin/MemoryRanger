#include "allocated_mem_access.h"

extern "C" namespace allocated_memory_access 
{
	CONFIG_THREAD configThread = { 0 };

	//////////////////////////////////////////////////////////////////////////

	NTSTATUS AllocatedMemoryAccess::allocate_set_secret() {

			#if defined  US_DATA
				char secret[30] = "Ernest Hemingway";
			#elif defined UK_DATA
				char secret[30] = "Charles Dickens";
			#elif defined RU_DATA
				char secret[30] = "Leo Tolstoy";
			#elif defined BUDGET
				char secret[30] = "Leo Tolstoy";
			#else
				char secret[30] = "Here is the secret";
			#endif // DATA_SECRET

		secretDataSz = 30;
		if (sizeof(secret) == secretDataSz) {
			_secretData = alignedExAllocatePoolWithTag(secretDataSz);
			if (_secretData) {
				RtlSecureZeroMemory(_secretData, secretDataSz);
				RtlCopyMemory(_secretData, secret, secretDataSz);
				RtlSecureZeroMemory(secret, secretDataSz);
			}
		}
		return STATUS_SUCCESS;
	}

	NTSTATUS AllocatedMemoryAccess::get_secret(PVOID inBuf, const ULONG inBufSz) {
		if (inBufSz == sizeof(SECRET_INFO)) {
			RtlCopyMemory(((PSECRET_INFO)inBuf)->SecretData, _secretData, secretDataSz);
			((PSECRET_INFO)inBuf)->SecretStart = (ULONG64)_secretData;
			((PSECRET_INFO)inBuf)->SecretSize = secretDataSz;
		}
		return STATUS_SUCCESS;
	}

	NTSTATUS AllocatedMemoryAccess::free_secret() {
		if (_secretData) {
			RtlSecureZeroMemory(_secretData, secretDataSz);
			alignedExFreePoolWithTag(_secretData);
		}
		return STATUS_SUCCESS;
	}
	void print_proc_info(void *buf, ULONG sz) {
		if (buf){
			PSYSTEM_BASIC_INFORMATION psys_info = (PSYSTEM_BASIC_INFORMATION)buf;
			MEM_ALLOCATOR_LOGGER("Shared Buf with SystemBasicInformation %I64X - %I64X", buf, sz);
			MEM_ALLOCATOR_LOGGER("Shared Buf: LowestPhysicalPage: %I64X (source address = %I64X )",
				psys_info->LowestPhysicalPage, &psys_info->LowestPhysicalPage);
			MEM_ALLOCATOR_LOGGER("Shared Buf: HighestPhysicalPage: %I64X (source address = %I64X )",
				psys_info->HighestPhysicalPage, &psys_info->HighestPhysicalPage);
		}
	}

	VOID memory_access_loop(_In_ PVOID StartContext) {
		configThread.flagLoopIsActive = true;
		REACTOR_CONFIG* p_data = (REACTOR_CONFIG*)StartContext;
		LARGE_INTEGER timeout = { 0 };
		timeout.QuadPart = (LONGLONG)(-1000 * 1000 * 10 * 5);  //  5s
		ULONG64 data = 0;
		while (configThread.flagLoopIsActive){

			__try {
				KeWaitForMutexObject(&configThread.mutex, Executive, KernelMode, FALSE, NULL);
				data = p_data->tempReactor;
				KeReleaseMutex(&configThread.mutex, FALSE);
			}
			__except (EXCEPTION_EXECUTE_FAULT) {
				data = 0;
			}
			MEM_ALLOCATOR_LOGGER("SCADA Buf addr: %I64X - %I64X ", p_data, sizeof(REACTOR_CONFIG) );
			MEM_ALLOCATOR_LOGGER("SCADA Buf: temperature = %X (address = %I64X )", data, &p_data->tempReactor );
			MEM_ALLOCATOR_LOGGER("============================================\r\n");
// 			print_proc_info(p_data->buf_for_ntos, p_data->buf_for_ntos_sz);
			KeDelayExecutionThread(KernelMode, FALSE, &timeout);
		}
	}

	NTSTATUS AllocatedMemoryAccess::update_thread(void* inbuf, void *outbuf) {
		REACTOR_CONFIG* p_data = configThread.pconfig_data;

		KeWaitForMutexObject(&configThread.mutex, Executive, KernelMode, FALSE, NULL);
		p_data->tempReactor = *(ULONG64*)inbuf;
		KeReleaseMutex(&configThread.mutex, FALSE);

		*((ULONG64*)outbuf) = ((ULONG64)&p_data->tempReactor);

		return STATUS_SUCCESS;
	}

	NTSTATUS AllocatedMemoryAccess::start_thread(void* inbuf, void *outbuf) {
		KeInitializeMutex(&configThread.mutex, 0);
		REACTOR_CONFIG *allocated_data = (REACTOR_CONFIG*)alignedExAllocatePoolWithTag(sizeof REACTOR_CONFIG);
		RtlSecureZeroMemory(allocated_data, sizeof REACTOR_CONFIG);
		allocated_data->tempReactor = *(ULONG64*)inbuf; // update value in the kernel memory
		*((ULONG64*)outbuf) = (ULONG64)&allocated_data->tempReactor; // return updated value to the console

// 			allocated_data->buf_for_ntos_sz = 0;
// 			ZwQuerySystemInformation(SystemBasicInformation, NULL, 0, &allocated_data->buf_for_ntos_sz);
// 			allocated_data->buf_for_ntos = ExAllocatePoolWithTag(NonPagedPool, allocated_data->buf_for_ntos_sz, armor_tag);
// 			if (allocated_data->buf_for_ntos) {
// 				ZwQuerySystemInformation(SystemBasicInformation, 
// 					allocated_data->buf_for_ntos, 
// 					allocated_data->buf_for_ntos_sz, 
// 					&allocated_data->buf_for_ntos_sz);
// 			}

		configThread.pconfig_data = allocated_data;
		NTSTATUS nt_status =
			PsCreateSystemThread(
				&configThread.handleMemoryLoop,
				THREAD_ALL_ACCESS, NULL, NULL, NULL,
				memory_access_loop, allocated_data);

		if (!NT_SUCCESS(nt_status)) {
			MEM_ALLOCATOR_LOGGER(" PsCreateSystemThread error %08X ", nt_status);
		}
		return nt_status;
	}

	NTSTATUS AllocatedMemoryAccess::start_set_thread(void* inbuf, void *outbuf){
		return (configThread.flagLoopIsActive == false) ?
			start_thread(inbuf, outbuf) :
			update_thread(inbuf, outbuf);
	}

	NTSTATUS AllocatedMemoryAccess::get_temp(PVOID inBuf, const ULONG inBufSz) {
		if (sizeof(ULONG64) == inBufSz) {
			if (configThread.flagLoopIsActive){
				KeWaitForSingleObject(&configThread.mutex, Executive, KernelMode, FALSE, NULL);
				*(ULONG64*)inBuf = configThread.pconfig_data->tempReactor;
				KeReleaseMutex(&configThread.mutex, FALSE);
			}
			else {
				*(ULONG64*)inBuf = 0;
			}
		}
		return STATUS_SUCCESS;
	}

	NTSTATUS AllocatedMemoryAccess::stop_this_thread() {
		NTSTATUS nt_status = STATUS_SUCCESS;
		if (configThread.flagLoopIsActive){
			configThread.flagLoopIsActive = false;
			nt_status = ObReferenceObjectByHandle(configThread.handleMemoryLoop,
				THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&configThread.pthread, NULL);
			if (NT_SUCCESS(nt_status)) {
				nt_status = KeWaitForSingleObject(configThread.pthread,
					Executive, KernelMode, FALSE, NULL);
				if (NT_SUCCESS(nt_status)) {
					ObDereferenceObject(configThread.pthread);
					if (configThread.pconfig_data) {
						alignedExFreePoolWithTag(configThread.pconfig_data);
					}
				}
			}
		}
		return nt_status;
	}
	
#include <intrin.h>
	void AllocatedMemoryAccess::calc_latency_stats(const int num_measures, ULONG64* rawDurations, const ULONG rawDurationsCount) {
		const ULONG64 temp_sz = 123;
		PVOID temp_buf = alignedExAllocatePoolWithTag(123);
		if (temp_buf){
			ULONG64 start_time = 0, end_time = 0;
			char read_param = 0;
			const unsigned long long CR0_original = __readcr0();
			unsigned long long CR0_nocache = CR0_original | 0x40000000; /* Disable and write back the cache */
			__writecr0(CR0_nocache);
			for (unsigned int i = 0; i < rawDurationsCount; i++) {
				start_time = __rdtsc();
				for (int loops = num_measures; loops--;) {
					read_param = 0;
					__wbinvd();   *(char *)temp_buf = (char)loops;
					__wbinvd();   read_param = *(char *)temp_buf;
				}
				end_time = __rdtsc();
				rawDurations[i] = end_time - start_time;
			}
			__writecr0(CR0_original);
			alignedExFreePoolWithTag(temp_buf);
		}
	}

	NTSTATUS AllocatedMemoryAccess::measure_latency(PVOID inBuf, ULONG inBufSz, PVOID outBuf, ULONG outBufSz) {
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		if (sizeof (LATENCY) == inBufSz){
			unsigned int num_measures = 0;
			ULONG64* raw_durations = NULL;
			ULONG raw_durations_count = outBufSz;
			__try {
				num_measures = ((LATENCY *)inBuf)->num_measures;
				raw_durations = (ULONG64*)outBuf;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				num_measures = 0;
			}
			if (num_measures) {

				calc_latency_stats(num_measures, raw_durations, raw_durations_count);

				nt_status = STATUS_SUCCESS;
			}
		}
		return nt_status;
	}
}