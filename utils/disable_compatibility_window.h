#ifndef __CONTROL_COMPATIBILITY_H__
#define __CONTROL_COMPATIBILITY_H__

#include "windows.h"
#include "gpedit.h" // IGroupPolicyObject

namespace disable_compatibility_window {

	//////////////////////////////////////////////////////////////////////////
	// two main functions

	/* Disable the Program Compatibility Assistant */
	bool disable();

	/* Enable the Program Compatibility Assistant */
	bool restore();

	//////////////////////////////////////////////////////////////////////////
	// three supplementary functions

	/* Stop service and set SERVICE_DISABLED*/
	bool stop_disable_service(LPCWSTR serviceName);

	/* Set SERVICE_AUTO_START and start service */
	bool enable_start_service(LPCWSTR serviceName);

	/* Control Program Compatibility Assistant via Group Policy Settings*/
	bool set_assistant_via_group_policy(DWORD value);
}

#endif // __CONTROL_COMPATIBILITY_H__