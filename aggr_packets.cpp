#include <iostream>

#include "aggr_packets.h"


using std::cout;
using std::endl;
using cap_file::pcap_data_holder;


pcap_data_holder::pcap_data_holder()
{
	number_of_packets = 0;
	}

void pcap_data_holder::output_content()
{
	cout<<"total number of packets:"<<number_of_packets<<endl;
	return;
	}

void pcap_data_holder::inc_num_of_pac()
{ 
	number_of_packets++;
	return;
	}	
