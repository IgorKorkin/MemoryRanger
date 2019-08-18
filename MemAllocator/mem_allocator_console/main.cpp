#include "windows.h"
#include <locale.h> // LC_ALL

#include "memory_allocator.h"
#include "..\shared\mem_allocator_shared.h" // strings defines

#include "resource.h"  // resource defines

#include <iostream>
#include "..\..\utils\console_font_colors.h" // add colors for the console

int wmain(int argc, wchar_t *argv[], wchar_t *envp[]) {

	argc; argv; envp; // to avoid warning C4100
	setlocale(LC_ALL, "");
	setvbuf(stdout, NULL, _IONBF, 0);

//	if (check_windows_support::is_ok()) 
	{
		memory_allocator::MemAllocator allocator;
		wchar_t buf[MAX_PATH] = {};
		swprintf_s(buf, MAX_PATH, L"The %s app", MEM_ALLOCATOR_NAME);
		SetConsoleTitle(buf);
		eku::setcolor(eku::bright_white, eku::defbackcol);
		if (allocator.is_ok(MEM_ALLOCATOR_RES_DRIVER, MEM_ALLOCATOR_SYS_FILE, MEM_ALLOCATOR_SERVNAME_APP, MEM_ALLOCATOR_LINKNAME_APP)) 
		{
			//allocator.print_driver_info();
			memory_allocator::init_input_commands();
			do {
				memory_allocator::print_supported_commands(eku::white, MEM_ALLOCATOR_NAME, MEM_ALLOCATOR_DETAILS);
				switch (memory_allocator::parse_call(allocator)) {
				case memory_allocator::PARSE_RESULT::WRONG:
					std::cout << eku::red << "---wrong input, try again---" << endl;
					break;
				case memory_allocator::PARSE_RESULT::QUIT:
					cin.ignore();
					cout << "Press enter to exit." << endl;
					cin.ignore(); // std::system("PAUSE");
					return 0;
				}
				cin.clear();
				//cin.ignore(10000, '\n');
				fflush(stdin);
				std::cout << endl;
			} while (true);
		}
	}
	getchar();
}