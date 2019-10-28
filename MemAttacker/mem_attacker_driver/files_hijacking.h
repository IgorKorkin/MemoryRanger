#pragma once

#include "..\..\utils\zwfile.h"
#include "mem_attacker_driver.h"

extern "C" namespace files_hijacking {

    bool HijAttOpenFile(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz);
    bool HijAttReadFile(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz);
    bool HijAttWriteFile(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz);
    bool HijAttCloseFile(zwfile::FileWriter & fw_open_file);

    bool HijAttOpenFileByHijackkingFileHandle(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz);
    
    bool copy_fileobj_fields(FILE_OBJECT * src, FILE_OBJECT * dst);
    bool HijAttOpenFileByHijackkingFileObj(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz);

    bool hijacking_fileobj_internals(FILE_OBJECT * src, FILE_OBJECT * dst);
    bool HijAttOpenFileByHijackingFileObjInternals(zwfile::FileWriter & fw_open_file, PVOID in_buf, ULONG in_buf_sz, PVOID out_buf, ULONG out_buf_sz);
}