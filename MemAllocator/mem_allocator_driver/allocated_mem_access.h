#ifndef __MEM_ALLOCATOR_ACCESS_H__
#define __MEM_ALLOCATOR_ACCESS_H__

#include "mem_allocator_driver.h"
#include "code_asm.h"
#include "math.h"


typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemUnused1,
	SystemPerformanceTraceInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemUnused3,
	SystemUnused4,
	SystemUnused5,
	SystemUnused6,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation

} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	ULONG PrivatePageCount;
	VM_COUNTERS VirtualMemoryCounters;
	IO_COUNTERS IoCounters;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_BASIC_INFORMATION { // Information Class 0 
	ULONG Unknown;
	ULONG MaximumIncrement;
	ULONG PhysicalPageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPage;
	ULONG HighestPhysicalPage;
	ULONG AllocationGranularity;
	ULONG LowestUserAddress;
	ULONG HighestUserAddress;
	ULONG ActiveProcessors;
	UCHAR NumberProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_INFORMATION { // Information Class 1 
	USHORT ProcessorArchitecture;
	USHORT ProcessorLevel;
	USHORT ProcessorRevision;
	USHORT Unknown;
	ULONG FeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;


extern "C"
{
	NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);
};


extern "C" namespace allocated_memory_access {

	/*Testbed structure to play with memory accesses*/

	/*  */
	typedef struct _CONFIG_THREAD {
		bool flagLoopIsActive;
		HANDLE handleMemoryLoop;
		PKTHREAD pthread;
		PREACTOR_CONFIG pconfig_data; /* PREACTOR_CONFIG pinit_data */
		KMUTEX mutex;
	}CONFIG_THREAD, *PCONFIG_THREAD;

	/*  */
	KSTART_ROUTINE memory_access_loop;

	/*  */
	extern CONFIG_THREAD configThread;

	class AllocatedMemoryAccess {
	private:
		unsigned int secretDataSz;
		char* secretData;
	public:

		NTSTATUS allocate_set_secret();

		/*  */
		NTSTATUS get_secret(PVOID inBuf, const ULONG inBufSz);

		NTSTATUS free_secret();

		//////////////////////////////////////////////////////////////////////////		

		/*  */
		NTSTATUS update_thread(void* inbuf, void *outbuf);

		/*  */
		NTSTATUS start_thread(void* inbuf, void *outbuf);

		/*  */
		NTSTATUS start_set_thread(void* inbuf, void *outbuf);

		/*  */
		NTSTATUS get_temp(PVOID inBuf, const ULONG inBufSz);

		/*  */
		NTSTATUS stop_this_thread();

		/*  */
		NTSTATUS measure_latency(PVOID inBuf, ULONG inBufSz, PVOID outBuf, ULONG outBufSz);

		/*  */
		void calc_latency_stats(const int num_measures, ULONG64* rawDurations, const ULONG rawDurationsCount);
	};
}

#endif // __MEM_ALLOCATOR_ACCESS_H__