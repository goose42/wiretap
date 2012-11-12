#ifndef _aggr_packets_H
#define _aggr_packets_H

#include <pcap/pcap.h>
namespace cap_file
{
	class pcap_data_holder
	{

		int number_of_packets;

		public:
		pcap_data_holder();
		void inc_num_of_pac(); 
		void output_content();


	};
} 


#endif
