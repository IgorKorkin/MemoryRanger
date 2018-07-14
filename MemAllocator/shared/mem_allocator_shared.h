#ifndef __MEM_ALLOCATOR_SHARED_H__
#define __MEM_ALLOCATOR_SHARED_H__

#include "version.h"

#if defined US_DATA
	#define		MEM_ALLOCATOR_NAME				L"MemAllocatorUS"
#elif defined UK_DATA
	#define		MEM_ALLOCATOR_NAME				L"MemAllocatorUK"
#elif defined RU_DATA
	#define		MEM_ALLOCATOR_NAME				L"MemAllocatorRU"
#endif


#define		MEM_ALLOCATOR_SYS_FILE			MEM_ALLOCATOR_NAME \
											L".sys"
// There are symbols for driver
#define		MEM_ALLOCATOR_DEVICENAME_DRV	L"\\Device\\dev" MEM_ALLOCATOR_NAME
#define		MEM_ALLOCATOR_LINKNAME_DRV 		L"\\DosDevices\\" MEM_ALLOCATOR_NAME

// There are symbols for command line app
#define		MEM_ALLOCATOR_LINKNAME_APP 		L"\\\\.\\" MEM_ALLOCATOR_NAME
#define		MEM_ALLOCATOR_SERVNAME_APP		MEM_ALLOCATOR_NAME

// Device type in user defined range
#define MEM_ALLOCATOR_DEVICE_IOCTL  0x8301
enum ALLOCATOR_COMMANDS {
	GET_DRIVER_INFO = 0x800,
	START_SET_THREAD,
	GET_TEMP,
	GET_SECRET, 
	STOP_THIS_THREAD,
	MEASURE_LATENCY,
	READ_MEMORY_BYTE,
	WRITE_MEMORY_BYTE,
};

// #define GET_DRIVER_INFO		 0x800
// #define START_SET_THREAD	 0x800+1
// #define GET_TEMP			 0x800+2
// #define STOP_THIS_THREAD	 0x800+3
// #define MEASURE_LATENCY		 0x800+4
// #define READ_MEMORY_BYTE	 0x800+5
// #define WRITE_MEMORY_BYTE	 0x800+6

#define MEM_ALLOCATOR_CTL_CODE(_Function_)   (unsigned) CTL_CODE(MEM_ALLOCATOR_DEVICE_IOCTL, (_Function_), METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _DRIVER_INFO {
	/* OUT */ ULONG64 DriverStart;
	/* OUT */ ULONG64 DriverSize;
}DRIVER_INFO;

#define MEM_ALLOCATOR_GET_DRIVER_INFO	 MEM_ALLOCATOR_CTL_CODE(GET_DRIVER_INFO)

/*  */
typedef struct _REACTOR_CONFIG
{
	ULONG64 param1;
	ULONG64 tempReactor; // temperature inside nuclear reactor, ha-ha
	ULONG64 presReactor; // pressure inside nuclear reactor, ha-ha
	ULONG64 param3;
	ULONG64 param4;
	// 		void* buf_for_ntos;
	// 		ULONG buf_for_ntos_sz;
}REACTOR_CONFIG, *PREACTOR_CONFIG;
#define MEM_ALLOCATOR_START_SET_THREAD	 MEM_ALLOCATOR_CTL_CODE(START_SET_THREAD)
#define MEM_ALLOCATOR_GET_TEMP			 MEM_ALLOCATOR_CTL_CODE(GET_TEMP)
#define MEM_ALLOCATOR_STOP_THIS_THREAD	 MEM_ALLOCATOR_CTL_CODE(STOP_THIS_THREAD)

/*  */
typedef struct _SECRET_INFO
{
	char SecretData[30];
	/* OUT */ ULONG64 SecretStart;
	/* OUT */ ULONG64 SecretSize;
}SECRET_INFO, *PSECRET_INFO;
#define MEM_ALLOCATOR_GET_SECRET		 MEM_ALLOCATOR_CTL_CODE(GET_SECRET)


typedef struct _LATENCY {
	/* IN */  unsigned int num_measures;
	/* OUT */ unsigned int average;
	/* OUT */ unsigned int deviation;
}LATENCY;
#define MEM_ALLOCATOR_MEASURE_LATENCY	 MEM_ALLOCATOR_CTL_CODE(MEASURE_LATENCY)

typedef struct _ADDR_BYTE {
	ULONG64 addr;
	unsigned char value;
}ADDR_BYTE;
#define MEM_ALLOCATOR_READ_MEMORY_BYTE	 MEM_ALLOCATOR_CTL_CODE(READ_MEMORY_BYTE)
#define MEM_ALLOCATOR_WRITE_MEMORY_BYTE	 MEM_ALLOCATOR_CTL_CODE(WRITE_MEMORY_BYTE)

#endif // __MEM_ALLOCATOR_SHARED_H__