#ifndef __TESTBED_CONSOLE_H__
#define __TESTBED_CONSOLE_H__

#include "windows.h"
#include "windef.h"
#include "stdlib.h"
#include "stdio.h" // sscanf_s, _snscanf_s
#include "Ntsecapi.h" // UNICODE_STRING
#include "resource.h"
#include "Shlwapi.h" // PathFileExists
#pragma comment(lib,"shlwapi.lib") // PathFileExists

#include "..\..\utils\drivers_launch_pad.h" // DriversLaunchPad
#include "..\..\utils\print_messages.h"
#include "..\shared\allmempro_shared.h" // IOCTL-codes


#include <iostream>
#include <algorithm>
#include <numeric>
#include <string>
#include <vector>
#include <map>

#include <iostream>
#include "..\..\utils\console_font_colors.h"


using namespace std;



namespace allocated_mem_protector{

	class MemProtector:public drivers_launch_pad::DriversLaunchPad {

	public:

		/*  */
		bool set_rule();

		/*  */
		bool print_rules();

		/*  */
		bool MemProtector::set_delta_to_cheat_tsc();
	};

	//////////////////////////////////////////////////////////////////////////

	typedef bool(allocated_mem_protector::MemProtector::*TControlFunc)(void);

	void add_unique_command(const std::string keyName, const TControlFunc keyFunction, const std::string def);

	void init_input_commands();

	void print_supported_commands(eku::BASIC_COLORS titlecolor, LPCTSTR name, LPCTSTR details);

	const enum class PARSE_RESULT : int {
		WRONG = -1,
		OK = 0,
		QUIT = 1,
	};

	PARSE_RESULT parse_call(allocated_mem_protector::MemProtector & my_testbed);
}

#endif // __TESTBED_CONSOLE_H__