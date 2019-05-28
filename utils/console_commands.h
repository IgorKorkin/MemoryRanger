#ifndef __CONSOLE_COMMANDS__
#define __CONSOLE_COMMANDS__

namespace console_commands {
	class ConsoleCommands
	{
	public:
		ConsoleCommands() {}
		~ConsoleCommands() {}

	private:
		typedef bool(memory_allocator::MemAllocator::*TControlFunc)(void);

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

	};

	




}

#endif // __CONSOLE_COMMANDS__