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
		bool read_one_byte();

		/* Write a byte to memory */
		bool write_one_byte();

		bool check_input_string(char *input) {
			bool b_res = false;
			size_t len = strlen(input);
			for (size_t i = 0; i < len; i++) {
				b_res = isgraph(input[i]) || isspace(input[i]);
				if (!b_res)   {   break;   }
			}
			if (!b_res) {
				cout << "  The input string:  \"" << input <<"\"  is wrong, try again!" << endl;
			}
			return b_res;
		}

		bool alloc_memory_pool() {
			bool b_res = false;
			ALLOCATED_DATA char_data = { 0 };
			cin.ignore(); // ignore one whitespace between the command and params
			cin.getline(char_data.content, sizeof(char_data.content));
			if (check_input_string(char_data.content)) {
				b_res =
					scm_manager.send_ctrl_code(MEM_ALLOCATOR_ALLOCATE_MEMORY, (LPVOID)&char_data, sizeof ALLOCATED_DATA, NULL, 0, 0);
				if (b_res) {
					allocated_addresses.push_back(char_data.address);
					cout << "  The data \"" << char_data.content << "\" has been allocated in "
						<< hex << uppercase << char_data.address << endl;
				}
			}			
			return b_res;
		}

		bool free_memory_pool() {
			bool b_res = false;
			ALLOCATED_DATA data = { 0 };
			std::cin >> std::hex >> data.address;
			auto item = find(allocated_addresses.begin(), allocated_addresses.end(), data.address);
			if (allocated_addresses.end() != item) {
				b_res =
					scm_manager.send_ctrl_code(MEM_ALLOCATOR_FREE_MEMORY_POOL, (LPVOID)&data, sizeof ALLOCATED_DATA, NULL, 0, 0);
				if (b_res) {
					cout << "  The allocation from "
						<< hex << uppercase << data.address <<
						" has been freed, bye memory.." << endl;
					allocated_addresses.erase(item);
				}
			}else {
				cout << "  The allocation from "
					<< hex << uppercase << data.address <<
					" is not found." << endl;
			}
			
			return b_res;
		}

		/* Read a char string from the memory */
		bool MemAllocator::read_char_data_non_secure() {
			ALLOCATED_DATA data = { 0 };
			std::cin >> std::hex >> data.address;
			bool b_res =
				scm_manager.send_ctrl_code(MEM_ALLOCATOR_READ_CHAR_DATA, (LPVOID)&data, sizeof ALLOCATED_DATA, NULL, 0, 0);
			if (b_res) {
				cout << "  We've just read  \"" << data.content << "\"  from  "
					<< hex << uppercase << data.address << endl;
			}
			return b_res;
		}

		bool MemAllocator::read_char_data() {
			bool b_res = false;
			ALLOCATED_DATA data = { 0 };
			std::cin >> std::hex >> data.address;
			auto item = find(allocated_addresses.begin(), allocated_addresses.end(), data.address);
			if (allocated_addresses.end() != item) {
				b_res =
					scm_manager.send_ctrl_code(MEM_ALLOCATOR_READ_CHAR_DATA, (LPVOID)&data, sizeof ALLOCATED_DATA, NULL, 0, 0);
				if (b_res) {
					cout << "  We've just read  \"" << data.content << "\"  from  "
						<< hex << uppercase << data.address << endl;
				}
			}
			else {
				cout << "  The allocation from "
					<< hex << uppercase << data.address <<
					" is not found." << endl;
			}
			return b_res;
		}

		/* Write a a char string to the memory */
		bool MemAllocator::write_char_data_non_secure() {
			bool b_res = false;
			ALLOCATED_DATA data = { 0 };
			std::cin >> std::hex >> data.address;
			cin.ignore(); // ignore one whitespace between the command and params
			cin.getline(data.content, sizeof(data.content));
			if (check_input_string(data.content)) {
				b_res =
					scm_manager.send_ctrl_code(MEM_ALLOCATOR_WRITE_CHAR_DATA, &data, sizeof ALLOCATED_DATA, NULL, 0, 0);
				if (b_res) {
					cout << "  We've just written  \"" << data.content << "\"  to the  "
						<< hex << uppercase << data.address << endl;
				}
			}
			return b_res;
		}

		bool MemAllocator::write_char_data() {
			bool b_res = false;
			ALLOCATED_DATA data = { 0 };
			std::cin >> std::hex >> data.address;
			if (allocated_addresses.end() != find(allocated_addresses.begin(), allocated_addresses.end(), data.address)) {
				cin.ignore(); // ignore one whitespace between the command and params
				cin.getline(data.content, sizeof(data.content));
				if(check_input_string(data.content)) {
					b_res =
						scm_manager.send_ctrl_code(MEM_ALLOCATOR_WRITE_CHAR_DATA, &data, sizeof ALLOCATED_DATA, NULL, 0, 0);
					if (b_res) {
						cout << "  We've just written  \"" << data.content << "\"  to the  "
							<< hex << uppercase << data.address << endl;
					}
				}
			}
			else {
				cout << "  The allocation from "
					<< hex << uppercase << data.address <<
					" is not found." << endl;
			}
			return b_res;
		}

		private:
			std::vector<void*> allocated_addresses;
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