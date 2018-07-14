#ifndef __DRIVERS_LAUNCH_PAD__
#define __DRIVERS_LAUNCH_PAD__

#include "windows.h"
#include "windef.h"
#include "stdlib.h"
#include "stdio.h" // sscanf_s, _snscanf_s
#include "Ntsecapi.h" // UNICODE_STRING

#include "Shlwapi.h" // PathFileExists
#pragma comment(lib,"shlwapi.lib") // PathFileExists

#include "print_messages.h"
#include "scm_util.h" // SCMUtil

#include "disable_compatibility_window.h" // Disable Program Compatibility Assistant 

#include <iostream>
using namespace std; // cout, print_os_info

namespace drivers_launch_pad{

	class DriversLaunchPad{

	protected:
		scm_util::SCMUtil scm_manager;

	public:
		bool is_ok(WORD resourceFile, LPCTSTR driverName, LPCTSTR serviceName, PCTCH symbolLink) {
			return activate_driver(resourceFile, driverName, serviceName, symbolLink);
		}

	private:
		/* extract driver via resource_functions::RESOURCE */
		bool extract_driver_file(WORD resourceFile, LPCTSTR driverName, TCHAR * binFile);

		/* load driver via scm_manager */
		bool load_driver_from_file(LPCTSTR serviceName, PCTCH symbolLink, TCHAR * binFile);

		/* extract and load driver, deactivate PCA*/
		bool activate_driver(WORD resourceFile, LPCTSTR driverName, LPCTSTR serviceName, PCTCH symbolLink);

	};

}

namespace check_windows_support {

	bool is_ok();

	void set_minimal_os_info(OSVERSIONINFOEX & os_info);

	void print_os_info(const char* title, const OSVERSIONINFOEX & os_version);
}

namespace resource_functions {

	typedef struct _RESOURCE
	{
		DWORD   data_sz;
		LPVOID  data;
	}RESOURCE, *PRESOURCE;

	bool extract(RESOURCE & resourse, LPCTSTR lpName, LPCTSTR lpType);

	bool set_tmp_file(LPCTSTR driverName, LPTSTR lpTempFileName);

	bool set_tmp_file_path(LPCTSTR lpPrefixString, LPTSTR lpTempFileName);
}

extern "C"
{
	NTSYSAPI BOOLEAN NTAPI RtlDosPathNameToNtPathName_U(
		__in PCWSTR DosFileName,
		__out UNICODE_STRING *NtFileName,
		__out_opt PWSTR *FilePart,
		__out_opt PVOID RelativeName
		);

#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_AMBIGUOUS   (0x00000001)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_UNC         (0x00000002)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_DRIVE       (0x00000003)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_ALREADY_DOS (0x00000004)

	typedef struct _RTL_BUFFER {
		PWCHAR        Buffer;
		PWCHAR        StaticBuffer;
		SIZE_T    Size;
		SIZE_T    StaticSize;
		SIZE_T    ReservedForAllocatedSize; // for future doubling
		PVOID     ReservedForIMalloc; // for future pluggable growth
	} RTL_BUFFER, *PRTL_BUFFER;

	typedef struct _RTL_UNICODE_STRING_BUFFER {
		UNICODE_STRING String;
		RTL_BUFFER     ByteBuffer;
		UCHAR          MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
	} RTL_UNICODE_STRING_BUFFER, *PRTL_UNICODE_STRING_BUFFER;

	NTSYSAPI NTSTATUS NTAPI RtlNtPathNameToDosPathName(
			__in ULONG Flags,
			__inout PRTL_UNICODE_STRING_BUFFER Path,
			__out_opt PULONG Disposition,
			__inout_opt PWSTR* FilePart
			);
};

#endif // __DRIVERS_LAUNCH_PAD__