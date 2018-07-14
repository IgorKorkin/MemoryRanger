
#include "disable_compatibility_window.h"

namespace disable_compatibility_window {

	bool disable() {
		// see details - https://www.howtogeek.com/howto/4161/disable-program-compatibility-assistant-in-windows-7-and-vista/
		return stop_disable_service(TEXT("PcaSvc")) &&
			set_assistant_via_group_policy(0); /* 0 - turn off or Disabled*/
	}

	bool restore() {
		return enable_start_service(TEXT("PcaSvc")) && 
			set_assistant_via_group_policy(1); /* 1 - turn on or Enabled*/
	}

	bool stop_disable_service(LPCWSTR serviceName) {
		auto b_res = false;
		// Get a handle to the SCM database. 
		auto schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (schSCManager) {
			auto schService = OpenService(schSCManager, serviceName, SERVICE_CHANGE_CONFIG | SERVICE_STOP);
			if (schService) {
				SERVICE_STATUS service_status = { 0 };
				b_res = ControlService(schService, SERVICE_CONTROL_STOP, &service_status) &&
					ChangeServiceConfig(schService, SERVICE_NO_CHANGE, SERVICE_DISABLED,
						SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
				CloseServiceHandle(schService);
			}
			CloseServiceHandle(schSCManager);
		}
		return b_res;
	}

	bool enable_start_service(LPCWSTR serviceName) {
		auto b_res = false;
		// Get a handle to the SCM database. 
		auto schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (schSCManager) {
			auto schService = OpenService(schSCManager, serviceName, SERVICE_CHANGE_CONFIG | SERVICE_START);
			if (schService) {
				b_res = ChangeServiceConfig(schService, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
					SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL) &&
					StartService(schService, 0, NULL);
				CloseServiceHandle(schService);
			}
			CloseServiceHandle(schSCManager);
		}
		return b_res;
	}

	bool set_assistant_via_group_policy(DWORD value) {
		// see details Group Policy Settings Reference for Windows and Windows Server
		// file Windows10andWindowsServer2016PolicySettings.xlsx
		// 		Turn off Program Compatibility Assistant
		// 		Machine
		// 		Windows Components\Application Compatibility
		// 		Software\Policies\Microsoft\Windows\AppCompat!DisablePCA

		auto b_res = false;
		IGroupPolicyObject* pLGPO = NULL; // see details - http://pete.akeo.ie/2011/03/porgramatically-setting-and-applying.html
		const IID my_IID_IGroupPolicyObject = { 0xea502723, 0xa23d, 0x11d1,{ 0xa7, 0xd3, 0x0, 0x0, 0xf8, 0x75, 0x71, 0xe3 } };
		const IID my_CLSID_GroupPolicyObject = { 0xea502722, 0xa23d, 0x11d1,{ 0xa7, 0xd3, 0x0, 0x0, 0xf8, 0x75, 0x71, 0xe3 } };

		const WCHAR key_name[] = TEXT("Software\\Policies\\Microsoft\\Windows\\AppCompat");
		const WCHAR value_name[] = TEXT("DisablePCA");

		// Create an instance of the IGroupPolicyObject class
		HRESULT hres = 0;
		if ((S_OK == (hres = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) &&
			(S_OK == (hres = CoCreateInstance(my_CLSID_GroupPolicyObject, NULL,
				CLSCTX_INPROC_SERVER, my_IID_IGroupPolicyObject, (LPVOID*)&pLGPO)))) {
			HKEY machine_key = { 0 };
			if ((S_OK == (hres = pLGPO->OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY))) &&
				(S_OK == (hres = pLGPO->GetRegistryKey(GPO_SECTION_MACHINE, &machine_key)))) {
				HKEY hkey = { 0 };
				// Create and set param 'Turn off Program Compatibility Assistant'
				if (ERROR_SUCCESS == RegCreateKeyEx(machine_key, key_name, 0, NULL, 0,
					KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &hkey, NULL)) {
					b_res =
						(ERROR_SUCCESS == RegSetValueEx(hkey, value_name,
							0, REG_DWORD, (byte*)&value, sizeof(value)));
				}
				RegCloseKey(hkey);
				// Apply policy and free resources
				GUID ext_guid = REGISTRY_EXTENSION_GUID;
				GUID snap_any_guid = { 0x3d271cfc, 0x2bc6, 0x4ac2,{ 0xb6, 0x33, 0x3b, 0xdf, 0xf5, 0xbd, 0xab, 0x2a } };
				pLGPO->Save(TRUE, TRUE, &ext_guid, &snap_any_guid);
				RegCloseKey(machine_key);
				pLGPO->Release();
			}
		}
		return b_res;
	}

}