// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to driver functions.

#ifndef __MEM_ALLOCATOR_DRIVER_H__
#define __MEM_ALLOCATOR_DRIVER_H__

#include "common.h"
#include "..\shared\mem_allocator_shared.h"
#include "allocated_mem_access.h"
#include "..\..\utils\zwfile.h"


extern "C" {

#define MEM_ALLOCATOR_LOGGER(format, ...) \
  DbgPrint("[%ws] ", MEM_ALLOCATOR_NAME); \
  DbgPrint((format), __VA_ARGS__); \
  DbgPrint("\r\n");


#if defined  US_DATA
	#define THE_TAG '-US-'
#elif defined UK_DATA
	#define THE_TAG '-UK-'
#elif defined RU_DATA
	#define THE_TAG '-UR-'
#elif defined BUDGET
	#define THE_TAG '-BD-'
#else
	#define THE_TAG 'SCRT'
#endif // DATA_SECRET

	/* Allocates a page-aligned buffer */
#if !defined(alignedExAllocatePoolWithTag)
#define alignedExAllocatePoolWithTag(NumberOfBytes)   \
		ExAllocatePoolWithTag(NonPagedPool, ( (NumberOfBytes) / PAGE_SIZE + 1)*PAGE_SIZE, THE_TAG);
#endif

#if !defined(alignedExFreePoolWithTag)
#define alignedExFreePoolWithTag(allocAddr)    \
 ExFreePoolWithTag( (allocAddr), THE_TAG);
#endif

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

#endif  // __MEM_ALLOCATOR_DRIVER_H__
