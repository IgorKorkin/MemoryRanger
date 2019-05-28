#include "drivers_launch_pad.h"

namespace drivers_launch_pad {

	bool DriversLaunchPad::extract_driver_file(WORD resourceFile, LPCTSTR driverName, TCHAR * binFile)
	{
		auto b_res = false;
		resource_functions::RESOURCE my_res = { 0 };
		RtlSecureZeroMemory(&my_res, sizeof(resource_functions::RESOURCE));
		if (resource_functions::extract(my_res, MAKEINTRESOURCE(resourceFile), TEXT("bin")) &&
			resource_functions::set_tmp_file(driverName, binFile)) {
			HANDLE h_file = NULL;
			if ((HANDLE)INVALID_HANDLE_VALUE != (h_file = CreateFile(
				binFile, GENERIC_WRITE, FILE_SHARE_READ, NULL,
				CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL))) {
				DWORD number_of_bytes = 0;
				if (WriteFile(h_file, my_res.data, my_res.data_sz, &number_of_bytes, NULL) &&
					(number_of_bytes == my_res.data_sz)) {
					b_res = true;
				}
				CloseHandle(h_file);
			}
			else {
				print_messages::print_last_err(L"err file %s ", binFile);
			}
		}
		return b_res;
	}

	bool DriversLaunchPad::load_driver_from_file(LPCTSTR serviceName, PCTCH symbolLink, TCHAR * binFile) {
		auto b_res = false;
		scm_manager.set_names(serviceName, binFile);
		scm_manager.stop_driver();
		scm_manager.remove_driver();
		if (scm_manager.add_driver()) {
			if (scm_manager.start_driver()) {
				if (INVALID_HANDLE_VALUE != scm_manager.open_device(symbolLink)) {
					b_res = true;
					//print_messages::print_mes(L"The [%s] driver is loaded!", serviceName);
					//	*for debugging process:
					// 	scm_manager.close_device(m_hNeither);
					// 	scm_manager.stop_driver();
					// 	scm_manager.remove_driver();
				}
				else {
					print_messages::print_last_err(L"err open device %s ", symbolLink);
				}
			}
			else {
				print_messages::print_last_err(L"err start driver %s %s", serviceName, binFile);
				scm_manager.stop_driver();
				scm_manager.remove_driver();
			}
		}
		else {
			print_messages::print_last_err(L"err add driver %s %s", serviceName, binFile);
			scm_manager.stop_driver();
			scm_manager.remove_driver();
		}
		scm_manager.delete_binfile();
		return b_res;
	}

	bool DriversLaunchPad::activate_driver(WORD resourceFile, LPCTSTR driverName, LPCTSTR serviceName, PCTCH symbolLink){
		TCHAR bin_file[MAX_PATH] = { 0 };
		disable_compatibility_window :: disable();
		auto const b_res = extract_driver_file(resourceFile, driverName, bin_file) &&
			load_driver_from_file(serviceName, symbolLink, bin_file);
		disable_compatibility_window :: restore();
		return b_res;
	}
} // namespace testbed 


namespace check_windows_support {

	bool is_ok() {
		OSVERSIONINFOEX os_info_needed = { 0 };
		set_minimal_os_info(os_info_needed);

		DWORDLONG dwlConditionMask = 0;
		VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_EQUAL);
		VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_EQUAL);
		VER_SET_CONDITION(dwlConditionMask, VER_BUILDNUMBER, VER_EQUAL);
		VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMAJOR, VER_EQUAL);
		VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMINOR, VER_EQUAL);

		auto b_res = (0 != VerifyVersionInfo(&os_info_needed,
			VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER |
			VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR, dwlConditionMask));

		if (b_res) {
			cout << "This OS is supported!" << endl;
		}
		else if (ERROR_OLD_WIN_VERSION == GetLastError()) {
			OSVERSIONINFOEX os_version = { 0 };
			RtlZeroMemory(&os_version, sizeof OSVERSIONINFOEX);
			os_version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
			if (GetVersionEx((LPOSVERSIONINFOW)&os_version)) {
				cout << "This OS is not supported" << endl;
				print_os_info("Current OS details:", os_version);
				print_os_info("The minimal OS requirements: Built by: 15063.0.amd64fre.rs2_release.170317-1834", os_info_needed);
			}
		}
		return b_res;
	}

	void set_minimal_os_info(OSVERSIONINFOEX & os_info) {
		/*
		Windows 7 Kernel Version 15063 MP (4 procs) Free x64
		Product: WinNt, suite: TerminalServer SingleUserTS
		Built by: 15063.0.amd64fre.rs2_release.170317-1834
		*/
		ZeroMemory(&os_info, sizeof(OSVERSIONINFOEX));
		os_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		os_info.dwMajorVersion = 6;
		os_info.dwMinorVersion = 2;
		os_info.dwBuildNumber = 9200; // or 0x23f0
		os_info.wServicePackMajor = 0;
		os_info.wServicePackMinor = 0;
	}

	void print_os_info(const char* title, const OSVERSIONINFOEX & os_version) {
		cout << title << endl;
		cout << " MajorVersion : " << std::dec << os_version.dwMajorVersion << std::hex << " (0x" << os_version.dwMajorVersion << ")" << endl;
		cout << " MinorVersion : " << std::dec << os_version.dwMinorVersion << std::hex << " (0x" << os_version.dwMinorVersion << ")" << endl;
		cout << " BuildNumber : " << std::dec << os_version.dwBuildNumber << std::hex << " (0x" << os_version.dwBuildNumber << ")" << endl;
		cout << " ServicePackMajor : " << std::dec << os_version.wServicePackMajor << std::hex << " (0x" << os_version.wServicePackMajor << ")" << endl;
		cout << " ServicePackMinor : " << std::dec << os_version.wServicePackMinor << std::hex << " (0x" << os_version.wServicePackMinor << ")" << endl;
	}
} // namespace check_windows_support

namespace resource_functions
{
	bool extract(RESOURCE & resourse, LPCTSTR lpName, LPCTSTR lpType) {
		HRSRC   res_handle = NULL;
		if ((NULL != (res_handle = FindResource(NULL, lpName, lpType))) &&
			(0 != (resourse.data_sz = SizeofResource(NULL, res_handle)))) {
			HGLOBAL data_handle = NULL;
			if (NULL != (data_handle = LoadResource(NULL, res_handle))) {
				resourse.data = LockResource(data_handle);
			}
		}
		return (NULL != resourse.data);
	}

	bool set_tmp_file_path(LPCTSTR lpPrefixString, LPTSTR lpTempFileName) {
		auto b_res = false;
		const DWORD uUnique = 0;
		wchar_t tmp_path[MAX_PATH] = { 0 };
		if (GetTempPath(MAX_PATH, tmp_path) &&
			GetTempFileName(tmp_path, lpPrefixString, uUnique, lpTempFileName)) {
			DeleteFile(lpTempFileName); // If uUnique is zero, GetTempFileName creates an empty file and closes it.
			b_res = (0 == wcscat_s(lpTempFileName, MAX_PATH, TEXT(".sys")));
			// lpTempFileName = <path>\<pre><uuuu>.TMP.sys
		}
		return b_res;
	}

	bool set_tmp_file(LPCTSTR driverName, LPTSTR lpTempFileName) {
		auto b_res = false;
		wchar_t tmp_path[MAX_PATH] = { 0 };
		if (GetTempPath(MAX_PATH, tmp_path)) {
			lpTempFileName[0] = 0;
			b_res =
				((0 == wcscat_s(lpTempFileName, MAX_PATH, tmp_path)) &&
					(0 == wcscat_s(lpTempFileName, MAX_PATH, driverName)));
			// lpTempFileName = <path>\lpTempFileName.sys
		}
		return b_res;
	}

} // namespace resource_functions