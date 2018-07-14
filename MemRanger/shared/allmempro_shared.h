#ifndef __ALLMEMPRO_SHARED_H__
#define __ALLMEMPRO_SHARED_H__

#define		ALLMEMPRO_NAME				L"AllMemPro"
#define		ALLMEMPRO_SYS_FILE			ALLMEMPRO_NAME \
										L".sys"
// There are symbols for driver
#define		ALLMEMPRO_DEVICENAME_DRV	L"\\Device\\dev" ALLMEMPRO_NAME
#define		ALLMEMPRO_LINKNAME_DRV 		L"\\DosDevices\\" ALLMEMPRO_NAME

// There are symbols for command line app
#define		ALLMEMPRO_LINKNAME_APP		L"\\\\.\\" ALLMEMPRO_NAME
#define		ALLMEMPRO_SERVNAME_APP		ALLMEMPRO_NAME


// Device type in user defined range
#define ALLMEMPRO_DEVICE_IOCTL  0x8301

#define ALLMEMPRO_ADD_MEMORY_ACCESS_RULE		(unsigned) CTL_CODE(ALLMEMPRO_DEVICE_IOCTL, 0x820, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _MEMORY_ACCESS_RULE {
	void*				drvStartAddr;
	unsigned __int64	drvSize;
	void*				allocStartAddr;
	unsigned __int64	allocSize;
	int					is_readable;
	int					is_overwritable;
}MEMORY_ACCESS_RULE, *PMEMORY_ACCESS_RULE;

// To provide CONFIDENTIALITY	 set 'is_readable=0'
// To provide	INTEGRITY		 set 'is_overwritable=0'
// 
// Comments:
// 1. The allocator from 'drvStartAddr-drvSize' have all access to 'allocStartAddr-allocSize'
// 2. if 'is_readable = 1' ==>> All other drivers can read this memory 
// 3. if 'is_readable = 0' ==>> All other drivers cannot read this memory 
//    To allow another driver from 'drvStartAddr2-drvSize2' read this memory
//    you have to add similar MEMORY_POLICY
// 4. if 'is_overwritable = 1' ==>> All other drivers can write to this memory 
// 5. if 'is_overwritable = 0' ==>> All other drivers cannot write to this memory 
//    To allow another driver from 'drvStartAddr2-drvSize2' write to this memory
//    you have to add similar MEMORY_POLICY

#define ALLMEMPRO_GET_MEMORY_ACCESS_RULES		(unsigned) CTL_CODE(ALLMEMPRO_DEVICE_IOCTL, 0x820+1, METHOD_NEITHER, FILE_ANY_ACCESS)

#define ALLMEMPRO_SET_TSC_DELTA			(unsigned) CTL_CODE(ALLMEMPRO_DEVICE_IOCTL, 0x820+2, METHOD_NEITHER, FILE_ANY_ACCESS)

#endif // __ALLMEMPRO_SHARED_H__