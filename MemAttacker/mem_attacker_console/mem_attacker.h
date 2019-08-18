#ifndef __MEM_ATTACKER_CONSOLE_H__
#define __MEM_ATTACKER_CONSOLE_H__

#include "payload_stack_overflow.h"
#include "payload_use_after_free.h"

#include "..\..\utils\drivers_launch_pad.h" // DriversLaunchPad
#include "..\..\utils\print_messages.h"
#include "..\shared\mem_attacker_shared.h" // IOCTL-codes
#include "..\..\utils\ctl_files.h"

#include <iostream>
#include <algorithm>
#include <numeric>
#include <string>
#include <vector>
#include <map>

#include <iostream>
#include "..\..\utils\console_font_colors.h"

namespace mem_attacker {

	class MemAttacker : public drivers_launch_pad::DriversLaunchPad
	{
	public:

		/* Set NT AUTHORITY\\SYSTEM privileges to the process */
		bool token_stealing();

		bool hijack_privs();

		/* Hide the process by unlinking EPROCESS structure, yep it causes 0x109 BSOD */
		bool hide_proc();

		/* Read a byte from the memory address */
		bool read_1byte();

		/* Write a byte to the memory address */
		bool write_1byte();

		/* Read a char string from the memory */
		bool read_char_data();

		/* Write a char string to the memory */
		bool write_char_data();

		//////////////////////////////////////////////////////////////////////////

		bool create_file();

		bool open_file();

		bool file_by_hijacking_fileobj();

		bool file_by_hijacking_filehandle();

		bool read_file();

		bool write_file();

		bool close_file();


		//////////////////////////////////////////////////////////////////////////

		/* Write 8 bytes to the memory */
		bool write_8bytes();

		/* Run stack overflow without any payload to calculate the required buffer size */
		bool run_simple_stack_overflow();

		/* Run stack overflow with the payload to escalate process privileges */
		bool run_stack_overflow_with_payload();

		/* Run a simple use-after-free exploit*/
		bool run_use_after_free();

		/* Run a use-after-free exploit with the payload to escalate process privileges */
		bool run_use_after_free_with_payload();

		/* Test pool allocations */
		bool test_pool_allocations();

		/* run pool overflow */
		bool run_pool_overflow();
	};

	//////////////////////////////////////////////////////////////////////////

	typedef bool(mem_attacker::MemAttacker::*TControlFunc)(void);

	void add_unique_command(const std::string keyName, const TControlFunc keyFunction, const std::string def);

	void init_input_commands();

	void print_supported_commands(eku::BASIC_COLORS titlecolor, LPCTSTR name, LPCTSTR details);

	const enum class PARSE_RESULT : int {
		WRONG = -1,
		OK = 0,
		QUIT = 1,
	};

	PARSE_RESULT parse_call(mem_attacker::MemAttacker & my_testbed);
}



#endif // ifndef __MEM_ATTACKER_CONSOLE_H__
