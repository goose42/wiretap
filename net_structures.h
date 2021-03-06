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

struct tcp_header 
{ 
	u_short th_sport;
	u_short th_dport;
	u_int th_seq;
	u_int th_ack;
	u_int8_t th_x2:4;
	u_int8_t th_of:4;
	u_char  th_flags;
	u_short th_win;        
	u_short th_sum;        
	u_short th_urp;        
};

 #define TH_FIN  0x01
 #define TH_SYN  0x02
 #define TH_RST  0x04
 #define TH_PUSH 0x08
 #define TH_ACK  0x10
 #define TH_URG  0x20

struct udphdr 
{
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};

struct icmphdr
{
  u_int8_t type;	
  u_int8_t code;		
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			
    u_int32_t	gateway;	
    struct
    {
      u_int16_t	__unused;
      u_int16_t	mtu;
    } frag;			
  } un;
};



 }


#endif	
