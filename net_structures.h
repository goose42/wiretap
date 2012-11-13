#ifndef _net_structs_h
#define _net_structs_h

#include <netinet/in.h> //else the u_char and u_short do not name a type

namespace cap_file
{
	struct eth
	{
		uint8_t e_dest[6];
		uint8_t e_src[6];
		uint16_t type;
		};
	
	
	
	}

#endif	
