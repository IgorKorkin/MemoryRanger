//////////////////////////////////////////////////////////////////////////
#ifndef __ICONS_H__
#define __ICONS_H__


//	THIS_VER_IS specifies the version of compiled files in the following way:
//   'A' - American version
//   'B' - British version
//   'R' - Russian version

#define THIS_VER_IS 'A' 
//#define THIS_VER_IS 'B' 
//#define THIS_VER_IS 'R' 

#if 'A' == THIS_VER_IS
	#define US_DATA
	#pragma message("Here is \"US\" version. To change it go to file: " __FILE__)
#elif 'B' == THIS_VER_IS
	#define UK_DATA
	#pragma message("Here is \"UK\" version. To change it go to file: " __FILE__)
#elif 'R' == THIS_VER_IS
	#define RU_DATA
	#pragma message("Here is \"RU\" version. To change it go to file: " __FILE__)
#else
	#error The version is undefined, please set THIS_VER_IS: 'A', 'B', or 'R'.
#endif

//The resource header file should have a blank line at the end
#endif // __ICONS_H__
