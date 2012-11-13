#include <iostream>

#include "aggr_packets.h"


using std::cout;
using std::endl;
using cap_file::pcap_data_holder;
using std::string;

pcap_data_holder::pcap_data_holder()
{
	number_of_packets = 0;
	}

void pcap_data_holder::output_content()
{ 
	typedef std::map<string,int>::const_iterator map_iter;
	cout<<"total number of packets:"<<number_of_packets<<endl;
	
	cout<<"******** Link Layer information ******"<<endl<<endl;
	cout<<"Here are the source MAC addresses:"<<endl;
	for (map_iter imap = src_mac.begin(); imap != src_mac.end(); imap++)
	{
		cout<<imap->first<<" -- "<<imap->second<<endl;
		
		}
	cout<<endl<<"Here are the destination MAC addresses:"<<endl;	
	for (map_iter imap = dest_mac.begin(); imap != dest_mac.end(); imap++)
	{
		cout<<imap->first<<" -- "<<imap->second<<endl;
		
		}
	return;
	}

void pcap_data_holder::inc_num_of_pac()
{ 
	number_of_packets++;
	return;
	}
	
void pcap_data_holder::add_MAC(string *src, string *dest)
{
	src_mac[*src]++;
	dest_mac[*dest]++;
	return;
	}		

