#ifndef __CTL_FILES_H__
#define __CTL_FILES_H__


#include "print_messages.h"
#include "scm_util.h"
#include "drivers_launch_pad.h"
#include "files_structs.h"

#include <iostream>
#include <algorithm>
#include <numeric>
#include <string>
#include <vector>
#include <map>
#include  <iomanip> // setfill, setw


extern "C" {
	ULONG RtlNtStatusToDosError(NTSTATUS Status);
}

namespace ctl_files {
	const char f_create_command[] = "f_create";
	const char f_create_descript[] = " <name> <content>' -- create the file <name> with the <content> ";

	const char f_open_command[] = "f_open";
	const char f_open_descript[] = " <file_name> <shared_access>' -- open the <file_name> with <shared_access>:\r\n\t\t\t'r'-read, 'w'-write, 'rw'-read+write, no flag - no shared access";
	
	const char f_open_by_hijacking_command[] = "f_open_by_hijacking";
	const char f_open_by_hijacking_descript[] = " <FILE_OBJECT>' -- access to an opened file with <FILE_OBJECT> by its hijacking";

	const char f_read_command[] = "f_read";
	const char f_read_descript[] = " <name> <content>' -- read the content of file <name>";

	const char f_write_command[] = "f_write";
	const char f_write_descript[] = " <name> <input>' -- write the <input> to the file <name>";

	const char f_close_command[] = "f_close";
	const char f_close_descript[] = " -- close the file";

	bool create_file(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode);
	
	bool open_file(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode);

	bool read_file(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode);

	bool write_file(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode);

	bool close_file(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode);

	bool open_file_by_hijacking(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode);
}

#endif // __CTL_FILES_H__