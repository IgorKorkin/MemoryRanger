#include "print_messages.h"

namespace print_messages
{
	void vspf(TCHAR *fmt, va_list argptr)
	{
		const int sz_wtmpbuf = MAX_PATH;
		WCHAR wtmpbuf[sz_wtmpbuf]; 
		memset(wtmpbuf, 0, sizeof(wtmpbuf));

#ifdef _CONSOLE
		_vsntprintf_s(wtmpbuf, sz_wtmpbuf - 2, _TRUNCATE, fmt, argptr);
		wcsncat_s(wtmpbuf, sz_wtmpbuf, TEXT("\r\n"), _TRUNCATE);
		//OutputDebugString(wtmpbuf);
		wprintf_s(wtmpbuf);
		fflush(stdout);
#else
		_vsntprintf_s(wtmpbuf, sz_wtmpbuf, _TRUNCATE, fmt, argptr);
		magic_add(wtmpbuf); // config to MFC, Qt or s/m else Gui app
#endif

	}

	void print_last_error(TCHAR *fmt, va_list argptr)
	{
		const int sz_wtmpbuf = MAX_PATH;
		WCHAR wtmpbuf[sz_wtmpbuf]; 
		memset(wtmpbuf, 0, sizeof(wtmpbuf));
		int	cnt = 0;
		if ((cnt = _vsntprintf_s(wtmpbuf, sz_wtmpbuf, _TRUNCATE, fmt, argptr)) != -1 )
		{
			LPTSTR lpMsgBuf;
			FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
				NULL,
				GetLastError(),
				MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), // Default language
				(LPTSTR) &lpMsgBuf,
				0,
				NULL);

#ifdef _CONSOLE
			_sntprintf_s(wtmpbuf + cnt, sz_wtmpbuf - cnt, _TRUNCATE, TEXT(" %s\r\n"), lpMsgBuf);
			wprintf_s(wtmpbuf);
			fflush(stdout);
#else
			_sntprintf_s(wtmpbuf + cnt, sz_wtmpbuf - cnt, _TRUNCATE, TEXT(" %s"), lpMsgBuf);
			magic_add(wtmpbuf); // config to MFC, Qt or s/m else
#endif

			LocalFree( lpMsgBuf );
		}
	}

	void vspf(char *fmt, va_list argptr)
	{
		const int sz_wtmpbuf = MAX_PATH;
		char wtmpbuf[sz_wtmpbuf];
		memset(wtmpbuf, 0, sizeof(wtmpbuf));

#ifdef _CONSOLE
		_vsnprintf_s(wtmpbuf, sz_wtmpbuf - 2, _TRUNCATE, fmt, argptr);
		strncat_s(wtmpbuf, sz_wtmpbuf, ("\r\n"), _TRUNCATE);
		//OutputDebugString(wtmpbuf);
		printf_s(wtmpbuf);
		fflush(stdout);
#else
		_vsntprintf_s(wtmpbuf, sz_wtmpbuf, _TRUNCATE, fmt, argptr);
		magic_add(wtmpbuf); // config to MFC, Qt or s/m else Gui app
#endif

	}

	void print_mes(TCHAR *fmt, ...)
	{
		va_list argptr;
		va_start(argptr, fmt);
		vspf(fmt, argptr);	
		va_end(argptr);
	}

	void print_mes(char *fmt, ...)
	{
		va_list argptr;
		va_start(argptr, fmt);
		vspf(fmt, argptr);
		va_end(argptr);
	}

	void print_last_err(TCHAR *fmt, ...)
	{
		va_list argptr;
		va_start(argptr, fmt);
		print_last_error(fmt, argptr);
		va_end(argptr);
	}

}