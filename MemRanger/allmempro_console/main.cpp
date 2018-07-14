
#include "windows.h"
#include "stdio.h"
#include "wchar.h"
#include <tchar.h>
#include <locale.h> // LC_ALL
#include "stdio.h"

#include <iostream>
#include <string>

#include "allmem_protector.h"
#include "resource.h"
#include "..\shared\allmempro_shared.h" // strings defines

using namespace std;

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
	argc; argv; envp; // to avoid warning C4100
	setlocale(LC_ALL, "");
	setvbuf(stdout, NULL, _IONBF, 0);

	//if (check_windows_support::is_ok()) 
	{
		allocated_mem_protector::MemProtector protector; // activate testbed
		if (protector.is_ok(ALLMEMPRO_RESOURCE, ALLMEMPRO_SYS_FILE, ALLMEMPRO_SERVNAME_APP, ALLMEMPRO_LINKNAME_APP)) 
		{
			allocated_mem_protector::init_input_commands();
			do {
				allocated_mem_protector::print_supported_commands();
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
}