
#include "ctl_files.h"

namespace ctl_files {

	bool check_string(char *input) {
		bool b_res = false;
		size_t len = strlen(input);
		for (size_t i = 0; i < len; i++) {
			b_res = isgraph(input[i]) || isspace(input[i]);
			if (!b_res) { break; }
		}
		if (!b_res) {
			cout << "  The input string:  \"" << input << "\"  is wrong, try again!" << endl;
		}
		return b_res;
	}

	bool check_string(TCHAR *input) {
		bool b_res = false;
		size_t len = _tcslen(input);
		for (size_t i = 0; i < len; i++) {
			b_res = _istgraph(input[i]) || _istspace(input[i]);
			if (!b_res) { break; }
		}
		if (!b_res) {
			wcout << "  The input string:  \"" << input << "\"  is wrong, try again!" << endl;
		}
		return b_res;
	}

	ULONG set_shared_access() {
		const char read_access[] = " r";
		const char write_access[] = " w";
		const char read_write_access[] = " rw";

#define FILE_SHARE_READ                 0x00000001  
#define FILE_SHARE_WRITE                0x00000002  
#define FILE_SHARE_DELETE               0x00000004  

		char shared_access[4] = { 0 };
		//cin.ignore(); // ignore one whitespace between the command and params
		if (cin.getline(shared_access, sizeof shared_access)) {
			if (0 == strcmp(shared_access, read_write_access)) {
				return FILE_SHARE_READ | FILE_SHARE_WRITE;
			}
			else if (0 == strcmp(shared_access, read_access)) {
				return FILE_SHARE_READ;
			}
			else if (0 == strcmp(shared_access, write_access)) {
				return FILE_SHARE_WRITE;
			}
		}
		return NULL;
	}

	const void print_object_handle(HANDLE handle, void* object) {
		cout << hex << uppercase << "  handle = " << handle
			<< "  FILE_OBJECT = " << object << endl;
	}

	const void print_details(long status, HANDLE handle, void* object, wchar_t* path) {
		if (status){
			wcout << "     ZwCreateFile() has failed with NTSTATUS " <<
				"0x"<< 
				setfill(__TEXT('0')) << setw(8) <<
				uppercase << hex << status << endl;

// 			SetLastError(RtlNtStatusToDosError(status));
// 			print_messages::print_last_err(TEXT("  Details: "));
		}
		else {
			wcout << "  The file is opened now \"" << path << "\"" << endl;
			print_object_handle(handle, object);
		}
	}
	
	bool set_path(const __in TCHAR * filename, __out FILE_PATH & file_path) {
		bool b_res = false;
		const int cur_dir_sz = MAX_PATH;
		TCHAR cur_dir[cur_dir_sz] = { 0 };
		if (GetCurrentDirectory(cur_dir_sz, cur_dir)) {
			UNICODE_STRING nt_name = { 0 };
			if (RtlDosPathNameToNtPathName_U(cur_dir, &nt_name, NULL, NULL)) {
				file_path.path_sz =
					_stprintf_s(file_path.path_to_file, MAX_PATH, L"%s\\%s", nt_name.Buffer, filename);
				b_res = (-1 != file_path.path_sz) ? true : false;;
			}
		}
		return b_res;
	}

	bool create_file(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode) {
		bool b_res = false;
		TCHAR filename[20] = { 0 };
		CREATE_THE_FILE file = { 0 };
		if (std::wcin >> filename && 
			check_string(filename) && 
			set_path(filename, file.file_path)) {
			cin.ignore(); // ignore one whitespace between the command and params
			if (cin.getline(file.content, sizeof file.content) && check_string(file.content)) {
				b_res = scm_manager.send_ctrl_code(ctrlCode, &file, sizeof CREATE_THE_FILE, NULL, 0, 0);
				if (b_res){
					wcout << "  The file has been created  \"" << file.file_path.path_to_file << "\"" << endl;
				}
			}
		}
		return b_res;
	}

	bool open_file(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode) {
		bool b_res = false;		
		TCHAR filename[20] = { 0 };
		OPEN_THE_FILE file = { 0 };
		if (std::wcin >> filename && check_string(filename) &&
			set_path(filename, file.file_path)) {
			file.shared_access = set_shared_access();
			b_res = scm_manager.send_ctrl_code(ctrlCode, &file, sizeof OPEN_THE_FILE, NULL, 0, 0);
			print_details(file.status, file.handle, file.object, file.file_path.path_to_file);
		}
		return b_res;
	}

	bool check_kernel_address(void *obj) {
		bool b_res = (obj > (void*)0xf0000000'00000000);
		if (!b_res){
			wcout << "  The input addr:  \"" << obj << "\"  is wrong, try again!" << endl;
		}
		return b_res;
	}

	bool open_file_by_hijacking_fileobj(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode) {
		bool b_res = false;
		OPEN_THE_FILE file = { 0 };
		const TCHAR filename[20] = __TEXT("hijack_file.txt");
		if (std::cin >> std::hex >> file.target_object && 
			check_kernel_address(file.target_object) &&
			set_path(filename, file.file_path)) {
			b_res = scm_manager.send_ctrl_code(ctrlCode, &file, sizeof OPEN_THE_FILE, NULL, 0, 0);
			if (file.is_hijacking_ok){
				wcout << "  The target FILE_OBJECT \"" << file.target_object << "\" has been hijacked!" << endl;
			}
			else {
				wcout << "  The target FILE_OBJECT \"" << file.target_object << "\" cannot be accessed." << endl;
			}
			print_details(file.status, file.handle, file.object, file.file_path.path_to_file);
		}
		return b_res;
	}

	bool open_file_by_hijacking_filehandle(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode) {
		bool b_res = false;
		HIJACKING_HANDLE_TABLE file = { 0 };
		const TCHAR filename[50] = __TEXT("hijack_file_by_handle_table.txt");
		if (std::cin >> std::hex >> file.target_file_handle && 
			check_kernel_address((void*)file.target_file_handle) &&
			set_path(filename, file.file_hijacker.file_path)) {
			b_res = scm_manager.send_ctrl_code(ctrlCode, &file, sizeof HIJACKING_HANDLE_TABLE, NULL, 0, 0);
			if (file.file_hijacker.is_hijacking_ok) {
				wcout << "  The target  HandleTableEntry  has been patched!" << endl;
			}
			else {
				wcout << "  The target  HandleTableEntry  cannot be patched." << endl;
			}
			print_details(file.file_hijacker.status, file.file_hijacker.handle, file.file_hijacker.object, file.file_hijacker.file_path.path_to_file);
		}
		return b_res;
	}

	bool read_file(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode) {
		READ_THE_FILE file = { 0 };
		bool b_res =
			scm_manager.send_ctrl_code(ctrlCode, &file, sizeof READ_THE_FILE, NULL, 0, 0);
		if (b_res) {
			wcout << "  The following data have been read  \"" << file.content << "\"" << endl;
			print_object_handle(file.handle, file.object);
		}
		return b_res;
	}

	bool write_file(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode) {
		bool b_res = false;
		WRITE_THE_FILE file = { 0 };
		cin.ignore(); // ignore one whitespace between the command and params
		if (cin.getline(file.content, sizeof file.content) && check_string(file.content)) {
			b_res =
				scm_manager.send_ctrl_code(ctrlCode,
					&file, sizeof WRITE_THE_FILE, NULL, 0, 0);
			if (b_res) {
				wcout << "  The following data have been written  \"" << file.content << "\"" << endl;
				print_object_handle(file.handle, file.object);
			}
		}
		return b_res;
	}

	bool close_file(scm_util::SCMUtil & scm_manager, const DWORD ctrlCode) {
		bool b_res = scm_manager.send_ctrl_code(ctrlCode, NULL, NULL, NULL, 0, 0);
		if (b_res) {
			wcout << "  The file is closed now." << endl;
		}
		return b_res;
	}
	
}