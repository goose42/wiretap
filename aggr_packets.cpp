#include <iostream>
#include <iomanip> //to get output formatting
#include <sstream>
#include "aggr_packets.h"


using std::cout;
using std::endl;
using cap_file::pcap_data_holder;
using std::string;
using std::setw;


pcap_data_holder::pcap_data_holder()
{
	number_of_packets = 0;
	}

void pcap_data_holder::output_content()
{ 
	typedef std::map<string,int>::const_iterator map_iter;
	cout<<"total number of packets:"<<number_of_packets<<endl;
	
	cout<<endl<<"******** Link Layer information ******"<<endl<<endl;
	cout<<"Here are the source MAC addresses:"<<endl;
	cout<<"Addresses | Number of occurences | %"<<endl<<endl;
	for (map_iter imap = src_mac.begin(); imap != src_mac.end(); imap++)
	{
		cout<<setw(16)<<imap->first<<" -- "<<setw(4)<<imap->second<<" -- "<<std::setprecision(2)<<(((float)imap->second / number_of_packets) * 100)<<"%"<<endl;

	}
	cout<<endl<<"Here are the destination MAC addresses:"<<endl;	
	cout<<"Addresses | Number of occurences | %"<<endl<<endl;
	for (map_iter imap = dest_mac.begin(); imap != dest_mac.end(); imap++)
	{
		cout<<setw(16)<<imap->first<<" -- "<<setw(4)<<imap->second<<" -- "<<std::setprecision(2)<<(((float)imap->second / number_of_packets) * 100)<<"%"<<endl;

	}
	
	cout<<endl<<"******** Network Layer information ******"<<endl<<endl;
	cout<<endl<<"Here are the Network layer protocols:"<<endl;	
//	cout<<"Addresses | Number of occurences | %"<<endl<<endl;
	for (map_iter imap = nw_proto.begin(); imap != nw_proto.end(); imap++)
	{
		cout<<setw(6)<<imap->first<<" -- "<<setw(4)<<imap->second<<" -- "<<std::setprecision(2)<<(((float)imap->second / number_of_packets) * 100)<<"%"<<endl;

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

void pcap_data_holder::add_network_protocol(int prot)
{
	std::stringstream temp;
	if (prot == 2048)
		nw_proto["IP"]++;
	else 
		if (prot == 2054)
			nw_proto["ARP"]++;
		else 
		{
			temp<<"0x"<<std::setw(4)<<std::setfill('0')<<std::hex<<prot;
			nw_proto[temp.str()]++;
		}


}
