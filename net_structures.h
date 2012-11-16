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

/*	struct arp
	{
		uint16_t arp_hard_type; 
		uint16_t arp_proto_type; 
		uint8_t  arp_hard_size;
		uint8_t  arp_proto_size;
		uint16_t arp_op;
		uint8_t  arp_eth_source[6];
		uint32_t arp_ip_source;
		uint8_t  arp_eth_dest[6];
		struct in_addr arp_ip_dest;
	};	*/

}

#endif	
