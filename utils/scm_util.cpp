#include "scm_util.h"

namespace scm_util
{
	/*  */
	SCMUtil :: SCMUtil(){
// 		display_name[0] = 0;
		service_name[0] = 0;
		driver_bin_path[0] = 0;
		symbol_link[0] = 0;
		handle_device = INVALID_HANDLE_VALUE;
		handle_scmanager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	}

	/*  */
	SCMUtil :: ~SCMUtil(){
		close_device(handle_device);
		stop_driver();
		remove_driver();
		CloseServiceHandle(handle_scmanager);
		handle_scmanager = NULL;
		delete_binfile();
	}

	/*  */
	bool SCMUtil :: set_names(LPCTSTR serviceName, LPCTSTR driverBinPath){
		return handle_scmanager && serviceName && !_tcscpy_s(service_name, serviceName) &&
// 					!_tcscpy_s(display_name, serviceName)
					driverBinPath && !_tcscpy_s(driver_bin_path, driverBinPath);
	}

	/*  */
	bool SCMUtil :: add_driver(){
		bool b_res = false;
		// SC_HANDLE service = CreateService (handle_scmanager, service_name, display_name, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driver_bin_path, NULL, NULL, NULL, NULL, NULL);
		
		SC_HANDLE service = CreateService (handle_scmanager, service_name, service_name, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driver_bin_path, NULL, NULL, NULL, NULL, NULL);

 		if ( service )
 			{   b_res = true;   }

		CloseServiceHandle(service);
		return b_res;
	}

	/*  */
	SC_HANDLE SCMUtil :: open_service(){
		SC_HANDLE handle_service = NULL;
		if (handle_scmanager){
			handle_service = OpenService(handle_scmanager, service_name, SERVICE_ALL_ACCESS);
		}
		return handle_service;
	}

	/*  */
	bool SCMUtil :: remove_driver(){
		bool b_res = false;
		SC_HANDLE service = open_service();
		if (service){
			if (DeleteService(service))
				{   b_res = true;   }
		}
		CloseServiceHandle(service);
		return b_res;
	}

	/*  */
	void SCMUtil :: delete_binfile()	{
		DeleteFile(driver_bin_path);
	}

	/*  */
	bool SCMUtil :: start_driver()	{
		bool b_res = false;
		SC_HANDLE service = open_service();
		if (service)		{	
			BOOLEAN bEnabled = true; // we have to load driver with SeLoadDriverPrivileges
 			if(RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &bEnabled) == 0) 			{
				if (StartService(service, 0, NULL)) 
					{   b_res = true;   }
			}
		}
		CloseServiceHandle(service);
		return b_res;
	}

	/*  */
	bool SCMUtil :: stop_driver(){
		bool b_res = false;
		SC_HANDLE service = open_service();
		if (service){
			SERVICE_STATUS service_status = {0};
			if (ControlService(service, SERVICE_CONTROL_STOP, &service_status))
				{   b_res = true;   }
		}
		CloseServiceHandle(service);
		return b_res;
	}

	/*  */
	HANDLE SCMUtil :: open_device(PCTCH symbolLink){
		handle_device = CreateFile(symbolLink, FILE_ALL_ACCESS, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
		return handle_device;
	}

	/*  */
	bool SCMUtil::close_device(HANDLE &hDevice){
		auto b_res = false;
		if (hDevice != INVALID_HANDLE_VALUE)	{
			b_res = (CloseHandle(hDevice) != 0) ? true : false;
			hDevice = INVALID_HANDLE_VALUE;
		}
		return b_res;
	}

	/*  */
	bool SCMUtil::close_device(){
		auto b_res = false;
		if (handle_device != INVALID_HANDLE_VALUE){
			b_res = (CloseHandle(handle_device) != 0) ? true : false;
			handle_device = INVALID_HANDLE_VALUE;
		}
		return b_res;
	}

	/*  */
	int SCMUtil :: read(HANDLE hDevice, LPVOID lpBuffer, DWORD nNumberOfBytesToRead){
		DWORD number_of_bytes_read = (DWORD)(-1);
		if (!ReadFile(hDevice, lpBuffer, nNumberOfBytesToRead, &number_of_bytes_read, NULL))
			{   number_of_bytes_read = (DWORD)(-1);   }
		return number_of_bytes_read;
	}

	/*  */
	int SCMUtil :: write(HANDLE hDevice, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite){
		DWORD number_of_bytes_written = (DWORD)(-1);
		if (!WriteFile(hDevice, lpBuffer, nNumberOfBytesToWrite, &number_of_bytes_written, NULL))
			{   number_of_bytes_written = (DWORD)(-1);   }
		return number_of_bytes_written;
	}

	/*  */
	bool SCMUtil::send_ctrl_code(const DWORD ctrlCode, LPVOID inBuf, DWORD inBufSize, LPVOID outBuf, DWORD outBufSize, LPOVERLAPPED lpOverlapped ){
		DWORD number_of_bytes_returned = (DWORD)(-1);
		bool b_res = false;
		if (DeviceIoControl(handle_device, ctrlCode, inBuf, inBufSize, outBuf, outBufSize, &number_of_bytes_returned, lpOverlapped))
			{   b_res = true;   }
		return b_res;
	}

	/*  */
	bool SCMUtil::send_ctrl_code(const DWORD ctrlCode, LPVOID inBuf, DWORD inBufSize, LPVOID outBuf, DWORD outBufSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) {
		bool b_res = false;
		if (DeviceIoControl(handle_device, ctrlCode, inBuf, inBufSize, outBuf, outBufSize, lpBytesReturned, lpOverlapped))
		{
			b_res = true;
		}
		return b_res;
	}

	/* check the presence of the driver in the list of active drivers */
	bool SCMUtil :: double_check_status(){
		bool b_res = false;
		DWORD bytes_needed = 0;
		DWORD resume_handle = 0;
		DWORD num_service_entries = 0;
		EnumServicesStatus(handle_scmanager, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,  NULL, 0, &bytes_needed, &num_service_entries, &resume_handle);
		
		LPENUM_SERVICE_STATUS m_pStatus = (LPENUM_SERVICE_STATUS)_aligned_malloc( bytes_needed , 4096);
		if (m_pStatus)	{
			memset( m_pStatus, 0, bytes_needed );

			if (EnumServicesStatus( handle_scmanager, SERVICE_DRIVER, SERVICE_ACTIVE, m_pStatus, bytes_needed, &bytes_needed, &num_service_entries, &resume_handle)){
				for (unsigned int i = 0 ; i < num_service_entries ; i++ ){
					if (wcsstr( m_pStatus[i].lpServiceName, service_name /*service_name*/) && 
						wcsstr( m_pStatus[i].lpDisplayName, service_name /*display_name*/))
					{   b_res = true;   break;   }
				}
			}
		}
		if (m_pStatus)   {   _aligned_free(m_pStatus);   }
		
		return b_res;
	}
}
