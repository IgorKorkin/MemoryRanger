
#include "windows.h"
#include "stdio.h"
#include "wchar.h"
#include <tchar.h>
#include <locale.h> // LC_ALL
#include "stdio.h"

#include <iostream>
#include <string>

#include "memory_ranger_console.h"
#include "resource.h"
#include "..\shared\memory_ranger_shared.h" // strings defines

#include <iostream>
#include "..\..\utils\console_font_colors.h" // add colors for the console

using namespace std;

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
	argc; argv; envp; // to avoid warning C4100
	setlocale(LC_ALL, "");
	setvbuf(stdout, NULL, _IONBF, 0);

	//if (check_windows_support::is_ok()) 
	{
		SetConsoleTitle(MEM_RANGER_NAME);
		eku::setcolor(eku::bright_white, eku::defbackcol);
		allocated_mem_protector::MemProtector protector; // activate testbed
		if (protector.is_ok(MEM_RANGER_SYS_RESOURCE, MEM_RANGER_SYS_FILE, MEM_RANGER_SERVNAME_APP, MEM_RANGER_LINKNAME_APP)) 
		{
			allocated_mem_protector::init_input_commands();
			do {
				allocated_mem_protector::print_supported_commands(eku::light_yellow, MEM_RANGER_NAME, MEM_RANGER_DETAILS);
				switch (allocated_mem_protector::parse_call(protector)) {
				case allocated_mem_protector::PARSE_RESULT::WRONG:
					std::cout << " ---wrong input, try again---" << endl;
					break;
				case allocated_mem_protector::PARSE_RESULT::QUIT:
					cin.ignore();
					cout << "Press enter to exit." << endl;
					cin.ignore(); // std::system("PAUSE");
					return 0;
				}
				cin.clear();
				cin.ignore(10000, '\n');
			} while (true);
		}
	}
	cout << "Press enter to exit." << endl;
	cin.ignore(); // std::system("PAUSE");
	return 0;
}