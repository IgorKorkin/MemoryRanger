#ifndef  __PRINT_MESSAGES_H__
#define  __PRINT_MESSAGES_H__

#include "tchar.h"
#include "windows.h"
#include "stdio.h"

namespace print_messages
{
	// public
	void print_mes(char *fmt, ...);
	void print_mes(TCHAR *fmt, ...);
	void print_last_err(TCHAR *fmt, ...);

	// private
	void vspf(TCHAR *fmt, va_list argptr);
	void print_last_error(TCHAR *fmt, va_list argptr);
}

#ifdef _DEBUG

	#define PRT_MES(__MESSAGE__)	print :: print_mes  __MESSAGE__ 
	#define PRT_ERR(__MESSAGE__)	print :: print_last_err  __MESSAGE__ 

#else

	#define DBG_MES(__MESSAGE__)
	#define DBG_ERR(__MESSAGE__)

#endif


#endif // __PRINT_MESSAGES_H__