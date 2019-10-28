#ifndef __MEM_ATTACKER_SHARED_H__
#define __MEM_ATTACKER_SHARED_H__

#include "..\..\utils\files_structs.h"

#define		MEM_ATTACKER_NAME					L"MemAttacker"
#define		MEM_ATTACKER_SYS_FILE				MEM_ATTACKER_NAME \
											L".sys"

#define		MEM_ATTACKER_DETAILS				L"accesses files and kernel-mode code & data illegally :["

// There are symbols for driver
#define		MEM_ATTACKER_DEVICENAME_DRV	L"\\Device\\dev" MEM_ATTACKER_NAME
#define		MEM_ATTACKER_LINKNAME_DRV 	L"\\DosDevices\\" MEM_ATTACKER_NAME

// There are symbols for command line app
#define		MEM_ATTACKER_LINKNAME_APP 	L"\\\\.\\" MEM_ATTACKER_NAME
#define		MEM_ATTACKER_SERVNAME_APP	MEM_ATTACKER_NAME



// Device type in user defined range
#define MEM_ATTACKER_DEVICE_IOCTL  0x8302

const enum ATTACKER_COMMANDS {
	HIDE_PROCESS = 0x800,
	TOKEN_STEALING,
	HIJACK_PRIVS,

	READ_1_BYTE,
	WRITE_1_BYTE,
	READ_CHAR_DATA,
	WRITE_CHAR_DATA,

	CREATE_FILE,
	OPEN_ONLY,
	OPEN_BY_HIJACK_FILEOBJ,
	OPEN_BY_HIJACK_FILEHANDLE,
    OPEN_BY_HIJACK_FILEOBJ_INTERNALS, 

	READ_FILE,
	WRITE_FILE,
	CLOSE_FILE,
	//////////////////////////////////////////////////////////////////////////
	WRITE_8_BYTES,
	SIMPLE_STACK_OVERFLOW,
	SIMPLE_POOL_OVERFLOW,
	UAF_ALLOCATE_OBJECT,
	UAF_FREE_OBJECT,
	UAF_USE_OBJECT,
	UAF_ALLOCATE_FAKE
};

#define MEM_ATTACKER_CTL_CODE(_Function_)   (unsigned) CTL_CODE(MEM_ATTACKER_DEVICE_IOCTL, (_Function_), METHOD_NEITHER, FILE_ANY_ACCESS)
//////////////////////////////////////////////////////////////////////////

#define MEM_ATTACKER_HIDE_PROCESS		MEM_ATTACKER_CTL_CODE(HIDE_PROCESS)
#define MEM_ATTACKER_TOKEN_STEALING		MEM_ATTACKER_CTL_CODE(TOKEN_STEALING)

typedef struct _HIJACK_PRIVS_DATA {
	__in	unsigned long	processID; /*DWORD*/
	__out	bool			is_privs_hijacking_ok;// 
}HIJACK_PRIVS_DATA, *PHIJACK_PRIVS_DATA;

#define MEM_ATTACKER_HIJACK_PRIVS		MEM_ATTACKER_CTL_CODE(HIJACK_PRIVS)



//////////////////////////////////////////////////////////////////////////

typedef struct _ADDR_BYTE {
	ULONG64 addr;
	unsigned char value;
}ADDR_BYTE;

#define MEM_ATTACKER_READ_1_BYTE		MEM_ATTACKER_CTL_CODE(READ_1_BYTE)
#define MEM_ATTACKER_WRITE_1_BYTE		MEM_ATTACKER_CTL_CODE(WRITE_1_BYTE)
//////////////////////////////////////////////////////////////////////////


typedef struct _ALLOCATED_DATA {
	char  content[20];
	void* address;
}ALLOCATED_DATA;
#define MEM_ATTACKER_READ_CHAR_DATA		MEM_ATTACKER_CTL_CODE(READ_CHAR_DATA )
#define MEM_ATTACKER_WRITE_CHAR_DATA	MEM_ATTACKER_CTL_CODE(WRITE_CHAR_DATA)
//////////////////////////////////////////////////////////////////////////

#define MEM_ATTACKER_CREATE_FILE	MEM_ATTACKER_CTL_CODE(CREATE_FILE)


#define MEM_ATTACKER_OPEN_ONLY			MEM_ATTACKER_CTL_CODE(OPEN_ONLY)
#define MEM_ATTACKER_OPEN_BY_HIJACKING_FILEOBJ		MEM_ATTACKER_CTL_CODE(OPEN_BY_HIJACK_FILEOBJ)
#define MEM_ATTACKER_OPEN_BY_HIJACKING_FILEHANDLE	MEM_ATTACKER_CTL_CODE(OPEN_BY_HIJACK_FILEHANDLE)

#define MEM_ATTACKER_OPEN_BY_HIJACKING_FILEOBJ_INTERNALS		MEM_ATTACKER_CTL_CODE(OPEN_BY_HIJACK_FILEOBJ_INTERNALS)



#define MEM_ATTACKER_READ_FILE		MEM_ATTACKER_CTL_CODE(READ_FILE)
#define MEM_ATTACKER_WRITE_FILE		MEM_ATTACKER_CTL_CODE(WRITE_FILE)
#define MEM_ATTACKER_CLOSE_FILE		MEM_ATTACKER_CTL_CODE(CLOSE_FILE)
//////////////////////////////////////////////////////////////////////////


typedef struct _ADDR_8BYTES {
	ULONG64 addr;
	ULONG64 value;
}ADDR_8BYTES;

#define MEM_ATTACKER_WRITE_8_BYTES	MEM_ATTACKER_CTL_CODE(WRITE_8_BYTES )
//////////////////////////////////////////////////////////////////////////


#define BUFFER_SIZE 512
#define MEM_ATTACKER_SIMPLE_STACK_OVERFLOW		MEM_ATTACKER_CTL_CODE(SIMPLE_STACK_OVERFLOW )

//////////////////////////////////////////////////////////////////////////

#define MEM_ATTACKER_SIMPLE_POOL_OVERFLOW		MEM_ATTACKER_CTL_CODE(SIMPLE_POOL_OVERFLOW )


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


#define MEM_ATTACKER_UAF_ALLOCATE_OBJECT	MEM_ATTACKER_CTL_CODE(UAF_ALLOCATE_OBJECT )
#define MEM_ATTACKER_UAF_FREE_OBJECT		MEM_ATTACKER_CTL_CODE(UAF_FREE_OBJECT )
#define MEM_ATTACKER_UAF_USE_OBJECT			MEM_ATTACKER_CTL_CODE(UAF_USE_OBJECT )
#define MEM_ATTACKER_UAF_ALLOCATE_FAKE		MEM_ATTACKER_CTL_CODE(UAF_ALLOCATE_FAKE )


#endif // __MEM_ATTACKER_SHARED_H__