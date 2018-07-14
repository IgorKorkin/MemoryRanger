#include "payloads.h"

namespace payloads{

	byte* _funcAddr = 0;
	DWORD _pidOffset = 0;

	bool process_is_running(const DWORD targetPid) {
		auto b_res = false;
		HANDLE h_proc = INVALID_HANDLE_VALUE;
		if (INVALID_HANDLE_VALUE != 
			(h_proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid))) {
			DWORD code = 0;
			if (GetExitCodeProcess(h_proc, &code) && (STILL_ACTIVE == code)) {
				b_res = true;
			}
			CloseHandle(h_proc);
		}
		return b_res;
	}

	bool set_pid_to_payload(const DWORD targetPid, const PAYLOAD_FUNC payloadFunc) {
		auto b_res = false;

		if (g_dwDefaultPid != targetPid) {
		// initialize or reset params only for users targetPid
			_funcAddr = 0;
			_pidOffset = 0;
		}

		// Retrieve function addr: from [JMP ADDR] we get [ADDR-value]
		// e.g.
		if (!_funcAddr) {
			byte* jmp_trampoline = (byte*)payloadFunc;
			if ((jmp_trampoline[0] == 0xE9) && (jmp_trampoline[5] == 0xE9)) {
				_funcAddr = jmp_trampoline +
					jmp_trampoline[1] +
					jmp_trampoline[2] * 0x100 +
					jmp_trampoline[3] * 0x100 * 0x100 +
					5;
				// The offset is relative to the end of the JMP instruction and not the beginning.
				// CURRENT_RVA: jmp (DESTINATION_RVA - CURRENT_RVA - 5 [sizeof(E9 xx xx xx xx)])
				// https://stackoverflow.com/questions/7609549/calculating-jmp-instructions-address
			}
		}

		if (!_pidOffset) {
			for (int i = 0; i < 0x64; i++) {
				if ((g_bDefaultPid[0] == _funcAddr[i]) &&
					(g_bDefaultPid[1] == _funcAddr[i + 1]) &&
					(g_bDefaultPid[2] == _funcAddr[i + 2]) &&
					(g_bDefaultPid[3] == _funcAddr[i + 3])) {
					_pidOffset = i;
					break;
				}
			}
		}

		if (_funcAddr && _pidOffset && targetPid) {
			__try {
				_funcAddr[_pidOffset] = (byte)(targetPid & 0x000000FF);
				_funcAddr[_pidOffset + 1] = (byte)((targetPid & 0x0000FF00) >> 8);
				_funcAddr[_pidOffset + 2] = (byte)((targetPid & 0x00FF0000) >> 8 * 2);
				_funcAddr[_pidOffset + 3] = (byte)((targetPid & 0xFF000000) >> 8 * 3);

				// We restore init configuration after setting targetPid as a g_dwDefaultPid
				// As a result we will be able to find these values in the memory again
				if (g_dwDefaultPid == targetPid){
					_funcAddr = 0;
					_pidOffset = 0;
				}
				b_res = true;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				b_res = false;
			}
		}
		return b_res;
	}

	bool set_memory_permission(const DWORD flNewProtect) {
		auto b_res = false;
		if (_funcAddr){
			auto handle_process = GetCurrentProcess();
			MEMORY_BASIC_INFORMATION info = { 0 };
			RtlZeroMemory(&info, sizeof MEMORY_BASIC_INFORMATION);
			for (unsigned char *p = NULL;
			VirtualQueryEx(handle_process, p, &info, sizeof(info)) == sizeof(info);
				p += info.RegionSize) {
				if (((size_t)info.BaseAddress <= (size_t)_funcAddr) &&
					((size_t)_funcAddr <= ((size_t)info.BaseAddress + info.RegionSize))) {
					DWORD old_protect = 0;
					b_res =
						(0 != VirtualProtectEx(handle_process,
							info.BaseAddress, info.RegionSize, flNewProtect, &old_protect));
					break;
				}
			}
		}
		return b_res;
	}
}