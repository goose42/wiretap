#ifndef _aggr_packets_H
#define _aggr_packets_H

#include <pcap/pcap.h>
#include <map>
#include <string>

using std::map;
using std::string;

namespace cap_file
{
	class pcap_data_holder
	{
		//summary
		int number_of_packets;
		int number_of_ip_packets;
		int number_of_tcp_packets;
		int number_of_udp_packets;
		int number_of_icmp_packets;
		//link layer
		map <string,int> src_mac;
		map <string,int> dest_mac;
		
		//network layer
		map <string,int> nw_proto;
		map <string,int> nw_src_ip;
		map <string,int> nw_dest_ip;
		map <int,int> nw_ttl;
		map <string, string> nw_arp;
		
		//transport layer
		map <string,int> tr_proto;
		//tcp
		map <int,int> tcp_srcports;
		map <int,int> tcp_desports;
		map <string,int> tcp_flags;
		//udp
		map <int,int> udp_srcports;
		map <int,int> udp_desports;
		//icmp
		map <string,int> icmp_src_ip;
		map <string,int> icmp_dest_ip;
	  map <int,int> icmp_type;
		map <int,int> icmp_code;	
		 
		public:
		pcap_data_holder();
		void inc_num_of_pac(); 
		void output_content();
		void add_MAC(string *, string *);
		void add_network_protocol(int);
		void add_source_ip(char *);
		void add_dest_ip(char *);
		void add_ttl(short unsigned int );
		void add_arp_participants(string*, string*);
		void add_transport_protocol(u_int8_t *);
		void add_tcp_ports(int, int);
	  void add_tcp_flags(string );
		void add_udp_ports(int*, int*);
		void add_icmp_ip(string *, string *);
		void add_icmp_type(int *);
		void add_icmp_code(int *);

	
	
	};
} 


#endif
