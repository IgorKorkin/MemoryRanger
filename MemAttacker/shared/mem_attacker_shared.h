#ifndef __MEM_ATTACKER_SHARED_H__
#define __MEM_ATTACKER_SHARED_H__

#define		MEM_ATTACKER_NAME					L"MemAttacker"
#define		MEM_ATTACKER_SYS_FILE				MEM_ATTACKER_NAME \
											L".sys"
// There are symbols for driver
#define		MEM_ATTACKER_DEVICENAME_DRV	L"\\Device\\dev" MEM_ATTACKER_NAME
#define		MEM_ATTACKER_LINKNAME_DRV 	L"\\DosDevices\\" MEM_ATTACKER_NAME

// There are symbols for command line app
#define		MEM_ATTACKER_LINKNAME_APP 	L"\\\\.\\" MEM_ATTACKER_NAME
#define		MEM_ATTACKER_SERVNAME_APP	MEM_ATTACKER_NAME

// Device type in user defined range
#define MEM_ATTACKER_IOCTL  0x8302

#define MEM_ATTACKER_HIDE_PROCESS		(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x840, METHOD_NEITHER, FILE_ANY_ACCESS)
#define MEM_ATTACKER_SET_PRIVS			(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x840+1, METHOD_NEITHER, FILE_ANY_ACCESS)

//////////////////////////////////////////////////////////////////////////

typedef struct _ADDR_BYTE {
	ULONG64 addr;
	unsigned char value;
}ADDR_BYTE;

#define MEM_ATTACKER_READ_1_BYTE		(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x850+1, METHOD_NEITHER, FILE_ANY_ACCESS)
#define MEM_ATTACKER_WRITE_1_BYTE	(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x850+2, METHOD_NEITHER, FILE_ANY_ACCESS)
//////////////////////////////////////////////////////////////////////////

typedef struct _ADDR_8BYTES {
	ULONG64 addr;
	ULONG64 value;
}ADDR_8BYTES;

#define MEM_ATTACKER_WRITE_8_BYTES	(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x860+3, METHOD_NEITHER, FILE_ANY_ACCESS)
//////////////////////////////////////////////////////////////////////////


#define BUFFER_SIZE 512
#define MEM_ATTACKER_SIMPLE_STACK_OVERFLOW		(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x810, METHOD_NEITHER, FILE_ANY_ACCESS)

//////////////////////////////////////////////////////////////////////////

#define MEM_ATTACKER_SIMPLE_POOL_OVERFLOW		(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x820, METHOD_NEITHER, FILE_ANY_ACCESS)


//////////////////////////////////////////////////////////////////////////
namespace payload_use_after_free {
	const int g_Objectsz = 0x54;
	typedef struct _BUFFER_OBJECT {
		char buffer[g_Objectsz];
	} BUFFER_OBJECT, *PBUFFER_OBJECT;

	typedef void(*FunctionPointer)();
	typedef struct _BUFFER_FUNC {
		FunctionPointer callback_func; // ! it must be always in the first place
		BUFFER_OBJECT object;
	} BUFFER_FUNC, *PBUFFER_FUNC;
}


#define MEM_ATTACKER_UAF_ALLOCATE_OBJECT	(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x830, METHOD_NEITHER, FILE_ANY_ACCESS)
#define MEM_ATTACKER_UAF_FREE_OBJECT		(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x830+1, METHOD_NEITHER, FILE_ANY_ACCESS)
#define MEM_ATTACKER_UAF_USE_OBJECT			(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x830+2, METHOD_NEITHER, FILE_ANY_ACCESS)
#define MEM_ATTACKER_UAF_ALLOCATE_FAKE		(unsigned) CTL_CODE(MEM_ATTACKER_IOCTL, 0x830+3, METHOD_NEITHER, FILE_ANY_ACCESS)


#endif // __TESTBED_SHARED_H__