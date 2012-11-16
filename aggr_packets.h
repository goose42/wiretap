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
		
		//link layer
		map <string,int> src_mac;
		map <string,int> dest_mac;
		
		//network layer
		map <string,int> nw_proto;
		map <string,int> nw_src_ip;
		map <string,int> nw_dest_ip;
		map <int,int> nw_ttl;
		map <string, unsigned int> nw_arp;
		
		//transport layer
		map <string,int> tr_proto;
		
		
		 
		public:
		pcap_data_holder();
		void inc_num_of_pac(); 
		void output_content();
		void add_MAC(string *, string *);
		void add_network_protocol(int);
		void add_source_ip(char *);
		void add_dest_ip(char *);
		void add_ttl(short unsigned int );
		void add_arp_participants(string*, unsigned int);
		void add_transport_protocol(u_int8_t *);
	
	
	
	};
} 


#endif
