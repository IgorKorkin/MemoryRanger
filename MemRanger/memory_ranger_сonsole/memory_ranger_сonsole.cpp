#include "memory_ranger_console.h"

namespace allocated_mem_protector {

	/*  */
	bool MemProtector::set_rule(){
		MEMORY_ACCESS_RULE memory_access_rule = { 0 };
		RtlZeroMemory(&memory_access_rule, sizeof MEMORY_ACCESS_RULE);
		cin >> std::hex >> memory_access_rule.drvStartAddr;
		cin >> std::hex >> memory_access_rule.drvSize;
		cin >> std::hex >> memory_access_rule.allocStartAddr;
		cin >> std::hex >> memory_access_rule.allocSize;

		auto b_res = 
			scm_manager.send_ctrl_code(MEM_RANGER_ADD_MEMORY_ACCESS_RULE, (LPVOID)&memory_access_rule, sizeof MEMORY_ACCESS_RULE, NULL, 0, 0);
		
		if (b_res){
			print_messages::print_mes(TEXT("the rule has been added"));
		}
		return b_res;
	}

	/*  */
	bool MemProtector::print_rules() {
		DWORD size = 0;
		if (scm_manager.send_ctrl_code(ALLMEMPRO_GET_MEMORY_ACCESS_RULES,
			NULL, 0, NULL, 0, &size, 0)){
			if (size){
				DWORD out_buf_sz = size;
				MEMORY_ACCESS_RULE* mem_rules = (MEMORY_ACCESS_RULE*)malloc(out_buf_sz);
				if (mem_rules) {
					RtlSecureZeroMemory(mem_rules, out_buf_sz);
					if (scm_manager.send_ctrl_code(ALLMEMPRO_GET_MEMORY_ACCESS_RULES,
						mem_rules, size, NULL, 0, &size, 0)) {
						print_messages :: print_mes(TEXT(" [POLICY] Active Data Protection [BEGIN]"));
// 						for (DWORD i = 0; i < size / (sizeof MEMORY_ACCESS_RULE); i++) {
// 							print_messages::print_mes(TEXT("  %d) memory %I64X-%I64X can be access only from driver %I64X-%I64X "),
// 								(i + 1),
// 								(mem_rules + i)->,
// 								(mem_rules + i)->allocSize,
// 								(mem_rules + i)->driverStart,
// 								(mem_rules + i)->drvSize);
// 						}
						print_messages::print_mes(TEXT(" [POLICY] Active Data Protection [END]"));
					}
					free(mem_rules);
				}
			}
			else {
				print_messages::print_mes(TEXT(" [POLICY] Active Data Protection list is empty "));
			}
		}
		return true;
	}

	bool MemProtector::set_delta_to_cheat_tsc() {
		auto b_res = false;
		ULONG64 delta = 0;
		std::cin >> std::hex >> delta;
		if (delta){
			b_res =
				scm_manager.send_ctrl_code(ALLMEMPRO_SET_TSC_DELTA, 
					(LPVOID)&delta, sizeof ULONG64, NULL, 0, 0);

			if (b_res) {
				print_messages::print_mes(TEXT("delta = %I64X has been set."), 
					delta);
			}
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
// 		add_unique_command("_rule", &allocated_mem_protector::MemProtector::set_rule, 
// 			" <DrvStartAddr> <DrvSz> <AllocStartAddr> <AllocSz>' -- add one rule");
// 		
// 		add_unique_command("_print", &allocated_mem_protector::MemProtector ::print_rules, 
// 			"' -- print the list of memory access rules");
// 		
		add_unique_command("_delta", &allocated_mem_protector::MemProtector ::set_delta_to_cheat_tsc, 
			" <delta in hex>' -- set delta to decrease TSC");
		
		add_unique_command("x", NULL, "' -- exit this app");
	}

	void print_supported_commands(eku::BASIC_COLORS titlecolor, LPCTSTR name, LPCTSTR details) {
		eku::setcolor(titlecolor, eku::defbackcol);

		std::wcout << name << " " << details << endl;

		eku::setcolor(eku::white, eku::defbackcol);
		for (const auto & item : g_CommandsList) {
			cout << " '" << item.first << item.second.key_definition << endl;
		}
	}

	PARSE_RESULT parse_call(allocated_mem_protector::MemProtector & my_testbed) {
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
} // namespace testbed 