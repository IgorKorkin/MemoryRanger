// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.


#ifndef TESTBED_COMMON_H_
#define TESTBED_COMMON_H_

#include <fltKernel.h>

// C30030: Calling a memory allocating function and passing a parameter that
// indicates executable memory
//
// Disable C30030 since POOL_NX_OPTIN + ExInitializeDriverRuntime is in place.
// This warning is false positive and can be seen when Target Platform Version
// equals to 10.0.14393.0.
#pragma prefast(disable : 30030)

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

/// Sets a break point that works only when a debugger is present
#if !defined(TESTBED_COMMON_DBG_BREAK)
#define TESTBED_COMMON_DBG_BREAK() \
  if (KD_DEBUGGER_NOT_PRESENT) {         \
  } else {                               \
    __debugbreak();                      \
  }                                      \
  reinterpret_cast<void*>(0)
#endif

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

/// Checks if a system is x64
/// @return true if a system is x64
constexpr bool IsX64() {
#if defined(_AMD64_)
  return true;
#else
  return false;
#endif
}

/// Checks if the project is compiled as Release
/// @return true if the project is compiled as Release
constexpr bool IsReleaseBuild() {
#if defined(DBG)
  return false;
#else
  return true;
#endif
}

#endif  // TESTBED_COMMON_H_
