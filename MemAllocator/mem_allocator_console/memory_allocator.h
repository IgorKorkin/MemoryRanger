#ifndef __MEM_ALLOCATOR_CONSOLE_H__
#define __MEM_ALLOCATOR_CONSOLE_H__

#include "windows.h"
#include "windef.h"
#include "stdlib.h"
#include "stdio.h" // sscanf_s, _snscanf_s
#include "Ntsecapi.h" // UNICODE_STRING

#include "..\..\utils\drivers_launch_pad.h" // DriversLaunchPad
#include "..\..\utils\print_messages.h"
#include "..\shared\mem_allocator_shared.h" // IOCTL-codes

#include <iostream>
#include <algorithm>
#include <numeric>
#include <string>
#include <vector>
#include <map>

using namespace std;

namespace memory_allocator{

	class MemAllocator : public drivers_launch_pad::DriversLaunchPad
	{
	public:
		/* print the loaded address of the driver and its size*/
		void print_driver_info();

		/* Imagine, that this function sets a param for a CNC-machine or for a nuclear reactor */
		bool start_set_thread();

		/* Get current temp of nuclear reactor */
		bool get_temp();

		/* get secret of */
		bool get_secret();

		/* Now, let's stop this thread */
		bool stop_this_thread();

		/* Measure the latency of memory access*/
		bool measure_latency();

		/* Read a one byte from memory */
		bool read_memory_byte();

		/* Write a byte to memory */
		bool write_memory_byte();
	};

	//////////////////////////////////////////////////////////////////////////

	
	typedef bool(memory_allocator::MemAllocator::*TControlFunc)(void);

	void add_unique_command(const std::string keyName, const TControlFunc keyFunction, const std::string def);

	void init_input_commands();

	void print_supported_commands(LPCTSTR name);

	const enum class PARSE_RESULT: int {
		WRONG = -1,
		OK = 0,
		QUIT = 1,
	};

	PARSE_RESULT parse_call(memory_allocator::MemAllocator & my_testbed);

}

#endif // __MEM_ALLOCATOR_CONSOLE_H__