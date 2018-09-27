#include "memory_allocator.h"

namespace memory_allocator {

	/*  */
	void MemAllocator::print_driver_info() {
		DRIVER_INFO driver_info = { 0 };
		RtlSecureZeroMemory(&driver_info, sizeof DRIVER_INFO);
		bool b_res = scm_manager.send_ctrl_code(MEM_ALLOCATOR_GET_DRIVER_INFO, &driver_info, sizeof DRIVER_INFO, 0, 0, 0);
		if (b_res){
			print_messages::print_mes(TEXT("The driver is loaded here 0x%I64X-0x%I64X "),
				driver_info.DriverStart, 
				driver_info.DriverStart + driver_info.DriverSize);
		}
	}


	/*  */
	bool MemAllocator::start_set_thread() {
		ULONG64 new_temp = 0;
		std::cin >> std::hex >> new_temp;

		ULONG64 addr_temp_in_krnl = 0;
		bool b_res = 
			scm_manager.send_ctrl_code(MEM_ALLOCATOR_START_SET_THREAD, (LPVOID)&new_temp, sizeof ULONG64, &addr_temp_in_krnl, sizeof ULONG64, 0);

		print_messages :: print_mes(TEXT("\t Temp  %I64X  is located here 0x%I64X "), new_temp, addr_temp_in_krnl);

		return b_res;
	}

	/*  */
	bool MemAllocator::get_temp() {
		ULONG64 temp = 0;
		bool b_res =
			scm_manager.send_ctrl_code(MEM_ALLOCATOR_GET_TEMP, 
				(LPVOID)&temp, sizeof ULONG64, NULL, 0, 0);

		print_messages::print_mes(TEXT("temp = %I64X "), temp);

		return b_res;
	}

	/*  */
	bool MemAllocator::get_secret() {
		SECRET_INFO secret_info = { 0 };
		bool b_res =
			scm_manager.send_ctrl_code(MEM_ALLOCATOR_GET_SECRET,
				(LPVOID)&secret_info, sizeof(SECRET_INFO), NULL, 0, 0);

		print_messages::print_mes("The secret \"%s\" is here %I64X-%I64X ",
			secret_info.SecretData,
			secret_info.SecretStart, 
			secret_info.SecretStart + secret_info.SecretSize);

		return b_res;
	}


	/*  */
	bool MemAllocator::stop_this_thread() {
		return
			scm_manager.send_ctrl_code(MEM_ALLOCATOR_STOP_THIS_THREAD, NULL, 0, NULL, 0, 0);
	}

	/* Measure the latency of memory access*/
	bool MemAllocator::measure_latency() {
		LATENCY latency = { 0 };
		unsigned int num_measures = 0;
		std::cin >> std::dec >> num_measures;
		bool b_res = false;
		if ( (0 < num_measures) && (num_measures < 100'000) ){
			latency.num_measures = num_measures;

			const int repeats = 200;
			vector<ULONG64> raw_durations(repeats);
			b_res =
				scm_manager.send_ctrl_code(MEM_ALLOCATOR_MEASURE_LATENCY, (LPVOID)&latency, sizeof LATENCY, raw_durations.data(), (DWORD)raw_durations.size(), 0);
			if (b_res) {
				sort(raw_durations.begin(), raw_durations.end());

				vector<ULONG64> filt_durations;
				filt_durations.assign(raw_durations.begin() + 5, raw_durations.end() - 5);

				double average = 1.0 * accumulate(filt_durations.begin(),
					filt_durations.end(), 0LL) / filt_durations.size();

				double variance = 0;
				for (const auto item : filt_durations) {
					variance += pow((average - item), 2);
				}
				double deviation = sqrt(variance / (filt_durations.size() - 1));

				cout << " =" << std::dec << (unsigned int)average << "+/-"
					<< std::dec << (unsigned int)deviation << endl;
			}
		}
		return b_res;
	}

	/* Read a one byte from memory */
	bool MemAllocator::read_one_byte() {
		ULONG64 address = 0;
		std::cin >> std::hex >> address;
		ADDR_BYTE addr_byte = { address, 0 };

		bool b_res =
			scm_manager.send_ctrl_code(MEM_ALLOCATOR_READ_MEMORY_BYTE, (LPVOID)&addr_byte, sizeof ADDR_BYTE, NULL, 0, 0);

		if (b_res) {
			const char symbol = isgraph((int)addr_byte.value) ? addr_byte.value : '?';
			cout << hex << uppercase
				<< "READ "
				<< "[" << addr_byte.addr << "] = 0x" << (addr_byte.value & 0xff)
				<< " or '" << symbol << "'" << endl;
		}
		return b_res;
	}

	/* Write a byte to memory */
	bool MemAllocator::write_one_byte() {
		ADDR_BYTE addr_byte = { 0 };
		cin >> std::hex >> addr_byte.addr;
		int16_t input = 0;
		cin >> std::hex >> (int16_t)input;
		addr_byte.value = (unsigned char)input;
		
		bool b_res =
			scm_manager.send_ctrl_code(MEM_ALLOCATOR_WRITE_MEMORY_BYTE, (LPVOID)&addr_byte, sizeof ADDR_BYTE, NULL, 0, 0);

		if (b_res) {
			const char symbol = isgraph((int)addr_byte.value) ? addr_byte.value : '?';
			cout << hex << uppercase
				<< "WRITE "
				<< "[" << addr_byte.addr << "] = 0x" << (addr_byte.value & 0xff)
				<< " or '" << symbol << "'" << endl;
		}
		return b_res;
	}

	//////////////////////////////////////////////////////////////////////////

	struct command_pair_triple {
		std::string key_definition;
		TControlFunc key_function;
	};

	map <std::string, command_pair_triple> g_CommandsList;

	void add_unique_command(const std::string keyName, const TControlFunc keyFunction, const std::string def) {
		for (const auto & item : g_CommandsList) {
			if ((keyFunction && (keyFunction == item.second.key_function)) ||
				(keyName == item.first)) {
				cout << "Internal error: two keys cannot have the same function" << endl;
				cout << "Press enter to exit." << endl;
				cin.ignore(); // std::system("PAUSE");
				exit(-1);
			}
		}
		g_CommandsList.insert({ keyName,{ def, keyFunction, } });
	}

	void init_input_commands() {
		/*
		'_starttemp <temp in hex>' -- start and set temp loop
		'_stoptemp' -- stop loop
		'exit' -- exit this app
		'q' -- fast quit
		*/

		add_unique_command("alloc",
			&memory_allocator::MemAllocator::alloc_memory_pool, 
			" <char[20]>' -- allocate memory and set char[20] as its content");

		add_unique_command("free",
			&memory_allocator::MemAllocator::free_memory_pool, 
			" <addr>' -- free allocated memory ");

		add_unique_command("read_data",
			&memory_allocator::MemAllocator::read_char_data_non_secure, 
			" <addr>' -- read char[] data from <addr> ");

		add_unique_command("write_data",
			&memory_allocator::MemAllocator::write_char_data_non_secure, 
			" <addr> <char[20]>' -- write char data[20]  to <addr> ");

		add_unique_command("read_byte",
			&memory_allocator::MemAllocator::read_one_byte, 
			" <addr>' -- read 1 byte from <addr>");

		add_unique_command("write_byte",
			&memory_allocator::MemAllocator::write_one_byte, 
			" <addr> <value>' -- write 1 byte with <value> to <addr>");

		add_unique_command("get_secret",
			&memory_allocator::MemAllocator::get_secret, 
			"' -- get secret data ");

		add_unique_command("latency",
			&memory_allocator::MemAllocator::measure_latency, 
			" <num of measures>' -- measure the memory access latency ");

// 		add_unique_command("_starttemp",
// 			&memory_allocator::MemAllocator::start_set_thread, " <temp in hex>' -- start and set temp ");
// 
// 		add_unique_command("_gettemp",
// 			&memory_allocator::MemAllocator::get_temp, "' -- get temp ");
// 
// 		add_unique_command("_stoptemp",
// 			&memory_allocator::MemAllocator::stop_this_thread, "' -- stop temp loop");

		add_unique_command("x", NULL, "' -- exit this app");
	}

	void print_supported_commands(LPCTSTR name) {
		std::wcout << name;
		std::cout << " allocates & accesses the data in the kernel-mode memory" << endl;
		for (const auto & item : g_CommandsList) {
			cout << " '" << item.first << item.second.key_definition << endl;
		}
	}

	PARSE_RESULT parse_call(memory_allocator::MemAllocator & my_testbed) {
		string string_command = { 0 };
		string_command = { 0 };
		std::cin >> string_command; //std::getline(std::cin >> std::ws, string_command);

		const auto item = g_CommandsList.find(string_command);

		if (item != g_CommandsList.end()) {
			if (NULL == item->second.key_function) {
				return PARSE_RESULT::QUIT; // quit, LET'S QUIT THIS APP.
			}
			else {
				(my_testbed.*item->second.key_function)();
				return PARSE_RESULT::OK; // success, LET'S PROCESS THIS COMMAND
			}
		}
		return PARSE_RESULT::WRONG; // wrong input command, UNKNOWN COMMAND
	}

} // namespace testbed 