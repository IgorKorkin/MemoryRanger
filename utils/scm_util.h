#ifndef __SCM_UTIL_H__
#define __SCM_UTIL_H__

#include "Windows.h"
#include "TCHAR.h"
#include "winsvc.h"
#include "WinIoCtl.h"

namespace scm_util
{
	class SCMUtil
	{
	private:
// 		TCHAR display_name[MAX_PATH];
		TCHAR service_name[MAX_PATH];
		TCHAR driver_bin_path[MAX_PATH];
		TCHAR symbol_link[MAX_PATH];
		HANDLE handle_device;
		SC_HANDLE handle_scmanager; // <- OpenSCManager handle
		
		SC_HANDLE open_service();
	public:
		
		SCMUtil();
	
		~SCMUtil();
		
		bool set_names(LPCTSTR serviceName, LPCTSTR driverBinPath);
		
		bool add_driver();
	
		bool remove_driver();
	
		void delete_binfile();
		
		bool start_driver();
		
		bool stop_driver();
		
		HANDLE open_device(PCTCH symbolLink);

		bool is_device_ok()
		{
			return (handle_device != INVALID_HANDLE_VALUE) ? true : false;
		}

		bool close_device(HANDLE &hDevice);

		bool close_device();
		
		int read(HANDLE hDevice, LPVOID lpBuffer, DWORD nNumberOfBytesToRead);
		
		int write(HANDLE hDevice, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite);
		
		bool send_ctrl_code(DWORD ctrlCode, LPVOID inBuf, DWORD inBufSize, LPVOID outBuf, DWORD outBufSize, LPOVERLAPPED lpOverlapped);
		
		bool send_ctrl_code(const DWORD ctrlCode, LPVOID inBuf, DWORD inBufSize, LPVOID outBuf, DWORD outBufSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);

		bool double_check_status();
		
	};

	#pragma comment(lib, "Advapi32.lib")  //   for EnumServicesStatus
	#pragma comment(lib, "ntdll.lib")  //  for RtlAdjustPrivilege

	#define SE_LOAD_DRIVER_PRIVILEGE 10L

	extern "C"
	{
		NTSYSAPI 
		NTSTATUS 
		NTAPI RtlAdjustPrivilege(
		ULONG    Privilege,
		BOOLEAN  Enable,
		BOOLEAN  CurrentThread,
		PBOOLEAN Enabled);
	}
}
#endif  //  __SCM_UTIL_H__