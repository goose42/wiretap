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
		
		//link layer
		map <string,int> src_mac;
		map <string,int> dest_mac;
		
		//network layer
		map <string,int> nw_proto;
		 
		public:
		pcap_data_holder();
		void inc_num_of_pac(); 
		void output_content();
		void add_MAC(string *, string *);
		void add_network_protocol(int);


	};
} 


#endif
