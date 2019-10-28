// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to driver functions.

#ifndef HYPERPLATFORM_DRIVER_H_
#define HYPERPLATFORM_DRIVER_H_

#include "common.h"
#include "global_object.h"
#include "hotplug_callback.h"
#include "log.h"
#include "power_callback.h"
#include "util.h"
#include "vm.h"
#include "performance.h"

#include "../MemoryMon/rwe.h"
#include "../MemoryMon/test.h"

#include "..\shared\memory_ranger_shared.h" // strings defines

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//
    typedef struct _EPROC_OFFSETS {
        int UniqueProcessId;
        int ActiveProcessLinks;
        int ActiveProcessLinksSize;
        int Token;
        int TokenSize;
        int ObjectTable; //      : Ptr64 _HANDLE_TABLE
    }EPROC_OFFSETS, *PEPROC_OFFSETS;

    extern EPROC_OFFSETS g_EprocOffsets;

    extern PSHORT NtBuildNumber;
////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

#endif  // HYPERPLATFORM_DRIVER_H_
