// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to driver functions.

#ifndef MEM_ATTACKER_DRIVER_H_
#define MEM_ATTACKER_DRIVER_H_

#include "common.h"
#include "..\shared\mem_attacker_shared.h" // IOCTL-codes
#include "vulnerable_code.h"

extern "C" {

	extern PSHORT NtBuildNumber;

NTKERNELAPI UCHAR *NTAPI PsGetProcessImageFileName(_In_ PEPROCESS process);

#define MEM_ATTACKER_LOGGER(format, ...) \
  DbgPrint("[%ws] ", MEM_ATTACKER_NAME); \
  DbgPrint((format), __VA_ARGS__); \
	DbgPrint("\r\n");
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

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

#endif  // MEM_ATTACKER_DRIVER_H_
