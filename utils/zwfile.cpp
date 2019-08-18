#include "zwfile.h"


void zw_open_file() {

}

extern "C"  namespace zwfile
{
	NTSTATUS create_directory(PCWSTR IN fullNameDir) {
		UNICODE_STRING unicode_file_name;
		RtlInitUnicodeString(&unicode_file_name, fullNameDir);

		OBJECT_ATTRIBUTES obj_attr = { 0 };
		InitializeObjectAttributes(&obj_attr,
			&unicode_file_name,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);

		HANDLE h_dir = NULL;
		IO_STATUS_BLOCK io_status = { 0 };
		NTSTATUS nt_status = ZwCreateFile(&h_dir,
			FILE_TRAVERSE | SYNCHRONIZE,
			&obj_attr,
			&io_status,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN_IF,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
			NULL,
			0);

		if (NT_SUCCESS(nt_status)) {
			nt_status = ZwClose(h_dir);
		}
		else {
			KdPrint(("ZwCreateFile( %ws ) = 0x%.8x \n", fullNameDir, nt_status));
		}

		return nt_status;
	}

	void get_handle_info(HANDLE m_File, SECURITY_INFORMATION SecurityInformation) {
		ULONG Length = 0;
		NTSTATUS nt_status = ZwQuerySecurityObject(m_File, SecurityInformation, NULL, 0, &Length);
		if (Length) {
			SECURITY_DESCRIPTOR *sec_desc = (SECURITY_DESCRIPTOR *)ExAllocatePool(NonPagedPool, Length);
			if (sec_desc) {
				RtlSecureZeroMemory(sec_desc, Length);
				nt_status = ZwQuerySecurityObject(m_File, SecurityInformation, sec_desc, Length, &Length);
				ExFreePool(sec_desc);
			}
		}
	}

	void get_secur_params() {
		// Managing Kernel Objects
		// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-kernel-objects
		// 
		// Microsoft Windows Security->Protecting Objects
		// https://www.microsoftpressstore.com/articles/article.aspx?p=2228450&seqNum=3
		//
		// "the object manager works with the Security Reference Monitor to enforce access rights."
		// http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.153.7946&rep=rep1&type=pdf
		//
		// The GrantedAccess field is a bitmask of type ACCESS_MASK which determines the set of operations that the particular handle permits on the object. The value of this field is computed by SeAccessCheck() based on the access requested by the caller (Desired Access) and the access allowed by the ACEs in the DACL in the security descriptor of the object.
		// https://www.codemachine.com/article_kernelstruct.html
		//
		// A Light on Windows 10's “OBJECT_HEADER->TypeIndex”
		// https://medium.com/@ashabdalhalim/a-light-on-windows-10s-object-header-typeindex-value-e8f907e7073a
		// 
		// Creates a section in an .obj file.
		// https://docs.microsoft.com/en-us/cpp/preprocessor/section?view=vs-2017
		// Example: 
		// #pragma section("secpol",read,write) 
		// __declspec(allocate("secpol")) 
		//	char byf[50*sizeof(MD5_hash)] = {AABBCCDEE}; 
		// 				PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
		// 				BOOLEAN SdAllocated = false;
		// 				nt_status = ObGetObjectSecurity(m_FileObject, &SecurityDescriptor, &SdAllocated);
		// 				if (NT_SUCCESS(nt_status)) {
		// 					ObReleaseObjectSecurity(SecurityDescriptor, SdAllocated);
		// 				}

		// 				FILE_DISPOSITION_INFORMATION fdi;
		// 				fdi.DeleteFile = TRUE;
		// 				nt_status = IoSetInformation(m_FileObject,
		// 					FileDispositionInformation,
		// 					sizeof(FILE_DISPOSITION_INFORMATION), &fdi); // http://xakep-archive.ru/xa/132/088/1.htm
		// 
		// 				get_handle_info(m_File, OWNER_SECURITY_INFORMATION);
		// 				get_handle_info(m_File, GROUP_SECURITY_INFORMATION);
		// 				get_handle_info(m_File, DACL_SECURITY_INFORMATION);
		// 				get_handle_info(m_File, SACL_SECURITY_INFORMATION);

		// 				ZwSetSecurityObject, IoCheckShareAccess, IoSetShareAccess
	}

	void print_share_more(DWORD dwShareMode) {
		KdPrint(("  ShareMode = "));
		switch (dwShareMode) {
		case (FILE_SHARE_READ | FILE_SHARE_WRITE) : KdPrint(("FILE_SHARE_READ | FILE_SHARE_WRITE \n")); break;
		case (FILE_SHARE_READ) : KdPrint(("FILE_SHARE_READ\n")); break;
		case (FILE_SHARE_WRITE) : KdPrint(("FILE_SHARE_WRITE\n")); break;
		default:				KdPrint(("NULL\n"));  break;
		}
	}
	void print_file_status(ULONG_PTR Information){
		KdPrint(("  IoStatusBlock = "));
		switch (Information) {
		case FILE_SUPERSEDED:	KdPrint(("FILE_SUPERSEDED\n")); break;
		case FILE_OPENED:		KdPrint(("FILE_OPENED\n")); break;
		case FILE_CREATED:		KdPrint(("FILE_CREATED\n")); break;
		case FILE_OVERWRITTEN:	KdPrint(("FILE_OVERWRITTEN\n")); break;
		case FILE_EXISTS:		KdPrint(("FILE_EXISTS\n")); break;
		case FILE_DOES_NOT_EXIST:	KdPrint(("FILE_DOES_NOT_EXIST\n")); break;
		default:				KdPrint(("..unknown IoStatus..\n")); break;
		}
	}
	NTSTATUS FileWriter::init(LPCWSTR lpFileName, ACCESS_MASK DesiredAccess /*= GENERIC_WRITE | GENERIC_READ*/, 
		DWORD dwCreationDisposition /*= FILE_OPEN_IF/*FILE_OVERWRITE_IF*/, DWORD dwShareMode /*= NULL*/)	{

		UNICODE_STRING us_filename;
		RtlInitUnicodeString(&us_filename, lpFileName);

		OBJECT_ATTRIBUTES object_attributes = { 0 };
		InitializeObjectAttributes( &object_attributes, &us_filename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		KdPrint(("%ws \n", lpFileName));
		IO_STATUS_BLOCK IoStatusBlock = { 0 };
		NTSTATUS nt_status = ZwCreateFile(
			&m_File,
			SYNCHRONIZE|DesiredAccess,
			&object_attributes,
			&IoStatusBlock,
			NULL,		// alloc size = none
			FILE_ATTRIBUTE_NORMAL,
			dwShareMode,
			dwCreationDisposition, //FILE_OPEN_IF,
			FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING,
			NULL,						// eabuffer
			0 );						// ealength

		if (NT_SUCCESS(nt_status)) {
			KdPrint(("ZwCreateFile (+) "));
			print_share_more(dwShareMode);
			print_file_status(IoStatusBlock.Information);

			nt_status = ObReferenceObjectByHandle(m_File, FILE_ALL_ACCESS/*NULL*/, *IoFileObjectType, KernelMode, (PVOID *)&m_FileObject, NULL);
			if (NT_SUCCESS(nt_status)) {
				KdPrint((" FileObject =  %I64X\n", m_FileObject));
				if (m_FileObject)   {   ObDereferenceObject(m_FileObject);   }
			}
			else {   KdPrint(("ObReferenceObjectByHandle err 0x%.8x \n", nt_status)); }
			
		}else
			{   KdPrint(( "ZwCreateFile( %ws ) = 0x%.8x \n", lpFileName, nt_status ));   }

		return nt_status;
	}

	unsigned __int64 FileWriter::read(LPVOID lpBuffer, DWORD nNumberOfBytesToRead){
		IO_STATUS_BLOCK io_status = { 0 };
		if (m_File) {			
			FILE_POSITION_INFORMATION file_pos = { 0 }; file_pos.CurrentByteOffset = { 0 };
			NTSTATUS nt_status = ZwSetInformationFile(m_File, &io_status, &file_pos, sizeof(file_pos), FilePositionInformation);
			if (NT_SUCCESS(nt_status)) {
				nt_status = ZwReadFile(m_File, NULL, NULL, NULL, &io_status, lpBuffer, nNumberOfBytesToRead, NULL, NULL);
				if (NT_SUCCESS(nt_status)) {
					KdPrint(("ZwReadFile() + \n"));
				}
				else {
					KdPrint(("ZwReadFile() = %08X \n", nt_status));
					io_status.Information = (ULONG_PTR)-1;
					if (STATUS_END_OF_FILE == nt_status) { 
						KdPrint((" this is the end of the file + \n"));
						io_status.Information = (ULONG_PTR)0;
					}
				}
				
			}else{
				KdPrint(("ZwSetInformationFile() = %08X \n", nt_status));
				io_status.Information = (ULONG_PTR)0;
			}
			
		}
		return io_status.Information;
	}

	unsigned __int64 FileWriter :: write( LPVOID lpBuffer, DWORD nNumberOfBytesToWrite ){
		IO_STATUS_BLOCK io_status = {0};
		if (m_File) {
			FILE_POSITION_INFORMATION file_pos = { 0 }; file_pos.CurrentByteOffset = { 0 };
			NTSTATUS nt_status = ZwSetInformationFile(m_File, &io_status, &file_pos, sizeof(file_pos), FilePositionInformation);
			if (NT_SUCCESS(nt_status)) {
				nt_status = ZwWriteFile(m_File, NULL, NULL, NULL, &io_status, lpBuffer, nNumberOfBytesToWrite, NULL, NULL);
				if (NT_SUCCESS(nt_status)) {
					KdPrint(("ZwWriteFile() + \n"));
				}
				else {
					KdPrint(("ZwWriteFile() = %08X \n", nt_status));
					io_status.Information = (ULONG_PTR)-1;
				}
			}
			else {
				KdPrint(("ZwSetInformationFile() = %08X \n", nt_status));
				io_status.Information = (ULONG_PTR)-1;
			}	
		}
		return io_status.Information;
	}	

	bool FileWriter :: init_sequental(LPCWSTR lpFileName)
	{
		UNICODE_STRING us_filename = {0};
		RtlInitUnicodeString(&us_filename, lpFileName);

		OBJECT_ATTRIBUTES ObjAttributes = {0};
		InitializeObjectAttributes(&ObjAttributes,
			&us_filename,
			OBJ_KERNEL_HANDLE,
			(HANDLE) NULL,
			(PSECURITY_DESCRIPTOR) NULL);

		IO_STATUS_BLOCK IoStatusBlock = {0};
		NTSTATUS nt_status = ZwCreateFile(&m_File,
			FILE_WRITE_ACCESS | SYNCHRONIZE,
			&ObjAttributes,
			&IoStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_SUPERSEDE,
			FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);

		if (!NT_SUCCESS(nt_status))
		{
			m_File = NULL;
			DbgPrint("Error: ZwCreateFile(dump) => %08X\n", nt_status);
		}

		return NT_SUCCESS(nt_status);
	}

	unsigned __int64 FileWriter::write_sequental(LPVOID lpBuffer, DWORD nNumberOfBytesToWrite)
	{
		IO_STATUS_BLOCK io_status = { 0 };

		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		if (m_File) {
			nt_status = ZwWriteFile(m_File, NULL, NULL, NULL, &io_status, lpBuffer, nNumberOfBytesToWrite, NULL, NULL);
			if (STATUS_PENDING == nt_status) {
				KdPrint(("ZwWaitForSingleObject . . .\n"));
// 				nt_status = ZwWaitForSingleObject(m_File, 0, 0);
// 				KdPrint(("ZwWaitForSingleObject ok!  \n"));
			}
			if (!NT_SUCCESS(nt_status)) {
				KdPrint(("ZwWriteFile() = %08X \n", nt_status));
				io_status.Information = (ULONG_PTR)-1;
			}
		}
		return io_status.Information;
	}

	/*   
	
	// Write the file
	ULONG 
		NTAPI
		WriteFile (
		HANDLE hFile, 
		PCVOID Buffer, 
		ULONG Length, 
		ULONG Position
		)
	{
		IO_STATUS_BLOCK IoStatus;
		NTSTATUS Status;
		LARGE_INTEGER Pos = {0};
		HANDLE hEvent;
		OBJECT_ATTRIBUTES EventAttributes;

		Pos.LowPart = Position;

		InitializeObjectAttributes (
			&EventAttributes,
			0, 0, 0, 0 );

		Status = ZwCreateEvent (
			&hEvent,
			EVENT_ALL_ACCESS,
			&EventAttributes,
			SynchronizationEvent,
			0 );

		if (!NT_SUCCESS(Status))
		{
			KdPrint (("ZwCreatEvent failed with status %08x\n", Status));
			return -1;
		}

		Status = ZwWriteFile (
			hFile,
			hEvent,
			NULL,
			NULL,
			&IoStatus,
			(PVOID) Buffer,
			Length,
			Position == -1 ? NULL : &Pos,
			NULL );

		if (Status == STATUS_PENDING)
		{
			Status = ZwWaitForSingleObject (hEvent, FALSE, NULL);
			Status = IoStatus.Status;
		}

		if (NT_SUCCESS(Status))
		{
			ZwClose (hEvent);
			return IoStatus.Information;
		}

		KdPrint (("ZwWriteFile failed with status %08x\n", Status));
		return -1;
	}
	
	*/

	unsigned __int64 strong_write(LPCWSTR lpFileName, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite )
	{
		HANDLE file = NULL;
		UNICODE_STRING usFile = {0};
		OBJECT_ATTRIBUTES oaFile = {0};
		IO_STATUS_BLOCK iosb = {0};

		RtlInitUnicodeString(&usFile, lpFileName);
		InitializeObjectAttributes(&oaFile,&usFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,NULL);
		IO_STATUS_BLOCK io_status = {0};

		NTSTATUS nt_status = ZwCreateFile(
			&file, 
			FILE_WRITE_ACCESS,
			&oaFile,
			&iosb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ, 
			FILE_OPEN_IF ,
			FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);

		/*  CreateDisposition value   Action if file exists     Action if file does not exist
		*   FILE_OPEN_IF                 Open the file               Create the file
		*/


		if (NT_SUCCESS(nt_status))
		{
			LARGE_INTEGER byte_offset = { (ULONG)-1, (LONG)FILE_WRITE_TO_END_OF_FILE};

			nt_status = ZwWriteFile( file, NULL, NULL, NULL, &io_status, lpBuffer, nNumberOfBytesToWrite, &byte_offset, NULL);

// 			if (nt_status == STATUS_PENDING)
// 			{
// 				nt_status = ZwWaitForSingleObject(file, 0, 0);
// 				if (!NT_SUCCESS(nt_status))
// 					{   KdPrint(( "ZwWaitForSingleObject() = %08X \n", nt_status ));   }
// 			}

			if (!NT_SUCCESS(nt_status))
			{
				KdPrint(( "ZwWriteFile() = %08X \n", nt_status ));
				io_status.Information = (ULONG_PTR)-1;
			}
			ZwClose(file);
		}
		return io_status.Information;
	}

	//////////////////////////////////////////////////////////////////////////

	void zw_create_file(ULONG inBufSz, void* inBuf) {
		if (inBufSz == sizeof CREATE_THE_FILE) {
			CREATE_THE_FILE *file = (CREATE_THE_FILE*)inBuf;
			if (file && file->file_path.path_sz && file->file_path.path_to_file && file->content) {
				size_t sz = wcslen(file->file_path.path_to_file);
				if (sz == file->file_path.path_sz) {
					zwfile::FileWriter fw_create_file;
					file->status = fw_create_file.init(file->file_path.path_to_file);
					if (NT_SUCCESS(file->status)) {
						char   data[80] = { 0 };
						fw_create_file.read(data, sizeof(data)); // -- The first attempt - we read nothing, status = C0000011
						KdPrint(("The current content is [%s] \n", data));
						if (sizeof(file->content) == fw_create_file.write(file->content, sizeof(file->content))) {
							RtlSecureZeroMemory(data, 80);
							if (sizeof(data) == fw_create_file.read(data, sizeof(data))) {
								KdPrint(("The current content is [%s] \n", data));
							}
						}
					}
					fw_create_file.close();
				}
			}
		}
	}

	bool zw_open_file(FileWriter & fwFile, ULONG inBufSz, void* inBuf) {
		bool b_res = false;
		if (inBufSz == sizeof OPEN_THE_FILE) {
			OPEN_THE_FILE *file = (OPEN_THE_FILE*)inBuf;
			if (file && file->file_path.path_sz && file->file_path.path_to_file) {
				size_t sz = wcslen(file->file_path.path_to_file);
				if (sz == file->file_path.path_sz) {
					file->status = fwFile.init(file->file_path.path_to_file,
						GENERIC_READ | GENERIC_WRITE, FILE_OPEN_IF, file->shared_access);
					if (NT_SUCCESS(file->status)) {
						b_res = true;
						file->handle = fwFile.get_handle();
						file->object = fwFile.get_object();
					}
				}
			}
		}
		return b_res;
	}

	void zw_read_file(FileWriter & fwFile, ULONG inBufSz, void* inBuf) {
		if (inBufSz == sizeof READ_THE_FILE) {
			READ_THE_FILE *file = (READ_THE_FILE*)inBuf;
			if (file) {
				fwFile.read(file->content, sizeof file->content);
				file->handle = fwFile.get_handle();
				file->object = fwFile.get_object();
			}
		}
	}

	void zw_write_file(FileWriter & fwFile, ULONG inBufSz, void* inBuf) {
		if (inBufSz == sizeof WRITE_THE_FILE) {
			WRITE_THE_FILE *file = (WRITE_THE_FILE*)inBuf;
			if (file) {
				if (sizeof file->content == fwFile.write(file->content, sizeof file->content)) {
					file->handle = fwFile.get_handle();
					file->object = fwFile.get_object();
				}
			}
		}
	}


}
