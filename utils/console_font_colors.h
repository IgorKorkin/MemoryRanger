/************************************************************************/
/* Add color to your console 2
   Published by eklavya sharma 2
   http://www.cplusplus.com/articles/Eyhv0pDG/
*/
/************************************************************************/

#ifndef _INC_EKU_IO_CONCOL
#define _INC_EKU_IO_CONCOL

/*Header file to color text and background in windows console applications
Global variables - textcol,backcol,deftextcol,defbackcol,colorprotect*/

#include<windows.h>
#include<iosfwd>

namespace eku
{

#ifndef CONCOL
#define CONCOL
	enum BASIC_COLORS
	{
		black = 0,
		dark_blue = 1,
		dark_green = 2,
		dark_aqua, dark_cyan=3,
		dark_red = 4,
		dark_purple, dark_pink, dark_magenta = 5,
		dark_yellow = 6,
		dark_white, light_gray = 7,
		gray = 8,
		light_blue = 9,
		light_green = 10,
		light_aqua, light_cyan = 11,
		red, light_red = 12,
		light_purple, light_pink, light_magenta = 13,
		light_yellow = 14,
		white, bright_white = 15
	};
	// See color examples - https://stackoverflow.com/questions/4053837/colorizing-text-in-the-console-with-c
#endif //CONCOL

	static HANDLE std_con_out;
	//Standard Output Handle
	static bool colorprotect=false;
	//If colorprotect is true, background and text colors will never be the same
	static BASIC_COLORS textcol,backcol,deftextcol,defbackcol;
	/*textcol - current text color
	backcol - current back color
	deftextcol - original text color
	defbackcol - original back color*/

	inline void update_colors()
	{
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(std_con_out,&csbi);
		textcol = BASIC_COLORS(csbi.wAttributes & 15);
		backcol = BASIC_COLORS((csbi.wAttributes & 0xf0)>>4);
	}

	inline void setcolor(BASIC_COLORS textcolor,BASIC_COLORS backcolor)
	{
		if(colorprotect && textcolor==backcolor)return;
		textcol=textcolor;backcol=backcolor;
		unsigned short wAttributes= (unsigned short)( ((unsigned int)backcol<<4) | (unsigned int)textcol );
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),wAttributes);
	}

	inline void settextcolor(BASIC_COLORS textcolor)
	{
		if(colorprotect && textcolor==backcol)return;
		textcol=textcolor;
		unsigned short wAttributes= (unsigned short)( ((unsigned int)backcol<<4) | (unsigned int)textcol );
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),wAttributes);
	}

	inline void setbackcolor(BASIC_COLORS backcolor)
	{
		if(colorprotect && textcol==backcolor)return;
		backcol=backcolor;
		unsigned short wAttributes= (unsigned short)( ((unsigned int)backcol<<4) | (unsigned int)textcol );
		SetConsoleTextAttribute(std_con_out,wAttributes);
	}

	inline void init_console_font_colors()
	{
		std_con_out=GetStdHandle(STD_OUTPUT_HANDLE);
		update_colors();
		deftextcol=textcol;defbackcol=backcol;
	}

	template<class elem,class traits>
	inline std::basic_ostream<elem,traits>& operator<<(std::basic_ostream<elem,traits>& os,BASIC_COLORS col)
	{os.flush();settextcolor(col);return os;}

	template<class elem,class traits>
	inline std::basic_istream<elem,traits>& operator>>(std::basic_istream<elem,traits>& is,BASIC_COLORS col)
	{
		std::basic_ostream<elem,traits>* p=is.tie();
		if(p!=NULL)p->flush();
		settextcolor(col);
		return is;
	}
	
}	//end of namespace eku

#endif	//_INC_EKU_IO_CONCOL 