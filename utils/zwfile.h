#ifndef __FILE_H_
#define __FILE_H_

#include "ntifs.h" // ZwQuerySecurityObject
#include "windef.h"
#include "..\..\utils\files_structs.h"

extern "C" namespace zwfile
{
	class FileWriter 
	{
		HANDLE m_File;
		PFILE_OBJECT m_FileObject;
		
	public:

		FileWriter() : m_File(NULL), m_FileObject(NULL) {  };

		void close() {
			if (m_File) {
				NTSTATUS nt_status = ZwClose(m_File);
				if (NT_SUCCESS(nt_status)){
					KdPrint(("ZwClose() +\n"));
				}
				else {
					KdPrint(("ZwClose() err 0x%.8x \n", nt_status));
				}
				m_File = NULL;
			}
		};
		
		//~FileWriter()   {   close();   };


		bool open_rw_without_sharing(LPCWSTR lpFileName) {
			return NT_SUCCESS(init(lpFileName, GENERIC_READ | GENERIC_WRITE, FILE_OPEN_IF, NULL));
		}

		NTSTATUS init(LPCWSTR lpFileName, ACCESS_MASK DesiredAccess = GENERIC_WRITE | GENERIC_READ, DWORD dwCreationDisposition = FILE_OPEN_IF/*FILE_OVERWRITE_IF*/, DWORD dwShareMode = NULL);
		
		unsigned __int64 read(LPVOID lpBuffer, DWORD nNumberOfBytesToRead);
		
		unsigned __int64 write( LPVOID lpBuffer, DWORD nNumberOfBytesToWrite );
		
		HANDLE get_handle()   {   return m_File;   }

		PFILE_OBJECT get_object()   {   return m_FileObject;   }

		bool init_sequental(LPCWSTR lpFileName);
		unsigned __int64 write_sequental( LPVOID lpBuffer, DWORD nNumberOfBytesToWrite );
	
	};

	unsigned __int64 strong_write(LPCWSTR lpFileName, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite );

	void zw_create_file(ULONG inBufSz, void* inBuf);
	void zw_open_file(FileWriter & fwFile, ULONG inBufSz, void* inBuf);
	void zw_read_file(FileWriter & fwFile, ULONG inBufSz, void* inBuf);
	void zw_write_file(FileWriter & fwFile, ULONG inBufSz, void* inBuf);
}

#endif // __FILE_H_