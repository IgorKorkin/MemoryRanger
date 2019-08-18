#include "file_system.h"

extern "C" {

	PHANDLE_TABLE_ENTRY g_HandleTableEntry = NULL;

	bool get_file_object(HANDLE fileHandle, PFILE_OBJECT & pfileObject) {
		NTSTATUS nt_status = ObReferenceObjectByHandle(fileHandle, FILE_ALL_ACCESS,
			*IoFileObjectType, KernelMode, (PVOID *)&pfileObject, NULL);
		if (NT_SUCCESS(nt_status)){
			if (pfileObject) { ObDereferenceObject(pfileObject); }
		}
		return NT_SUCCESS(nt_status);
	}


	typedef struct _GetHandleTableEntry {
		HANDLE Handle;
		void * HandleTableEntry;
	}GetHandleTableEntry, *PGetHandleTableEntry;

	/// <summary>
	/// Handle enumeration callback
	/// </summary>
	/// <param name="HandleTable">Process handle table</param>
	/// <param name="pHandleTableEntry">Handle entry</param>
	/// <param name="Handle">Handle value</param>
	/// <param name="EnumParameter">User context</param>
	/// <returns>TRUE when desired handle is found</returns>
	BOOLEAN walkthrough_handle_table_and_get_addr(
		IN PHANDLE_TABLE HandleTable,
		IN PHANDLE_TABLE_ENTRY HandleTableEntry,
		IN HANDLE Handle,
		IN PVOID EnumParameter
	) {
		BOOLEAN result = FALSE;
		if (EnumParameter != NULL) {
			PGetHandleTableEntry file = (PGetHandleTableEntry)EnumParameter;
			if (Handle == file->Handle) {
				if (ExpIsValidObjectEntry(HandleTableEntry)) {
					// copy the address of the HandleTableEntry
					file->HandleTableEntry = HandleTableEntry;
					result = TRUE;
				}
			}
		}
		// Release implicit locks
		_InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
		if (HandleTable != NULL && HandleTable->HandleContentionEvent)
			ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
		return result;
	}

	bool get_objheaderbits_in_handle_table_entry(HANDLE fileHandle, void* & handle_table_entry) {
		PEPROCESS pProcess = NULL;
		const HANDLE system_pid = (HANDLE)4;
		if (NT_SUCCESS(PsLookupProcessByProcessId(system_pid, &pProcess))) {
			PHANDLE_TABLE pTable =
				*(PHANDLE_TABLE*)((PUCHAR)pProcess + 0x418 /*dynData.ObjTable*/);
			
			GetHandleTableEntry get_entry = { 0 };
			get_entry.Handle = ObKernelHandleToHandle(fileHandle);
			get_entry.HandleTableEntry = 0;
			if ((TRUE == ExEnumHandleTable(pTable, &walkthrough_handle_table_and_get_addr, &get_entry, NULL)) && 
				get_entry.HandleTableEntry){
				handle_table_entry = get_entry.HandleTableEntry;
				handle_table_entry = (void*)((char*)handle_table_entry + OBJECTPOINTERBITS_OFFSET);
			}
			else   {   handle_table_entry = 0;   }
		}
		return (handle_table_entry != 0);
	}
}