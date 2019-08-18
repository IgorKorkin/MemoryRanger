#ifndef __FILES_STRUCTS__
#define __FILES_STRUCTS__

typedef struct _FILE_PATH {
	__in	int 			path_sz; // = wsclen(path_to_file)
	__in	wchar_t 		path_to_file[260];
}FILE_PATH, *PFILE_PATH;

typedef struct _CREATE_THE_FILE {
	__in	FILE_PATH		file_path;
	__in	char 			content[80];
	__out	long			status;
}CREATE_THE_FILE;


typedef struct _OPEN_THE_FILE {
	__in	FILE_PATH		file_path;
	__in	unsigned long	shared_access;
	__out	void*			handle;
	__out	void*			object;
	__out	long			status;
	__in	void*			target_object; // - for illegal access to the opened file
	__out	bool			is_hijacking_ok;// 
}OPEN_THE_FILE;

typedef struct _READ_THE_FILE {
	__in	void*			handle;
	__out	void*			object;
	__inout	char 			content[80];
	__out	long			status;
}READ_THE_FILE, WRITE_THE_FILE;


typedef struct _HIJACKING_HANDLE_TABLE{
	OPEN_THE_FILE file_hijacker;
	__in	void* target_file_handle; // - for illegal access to the opened file
} HIJACKING_HANDLE_TABLE, *PHIJACKING_HANDLE_TABLE;

#endif // __FILES_STRUCTS__