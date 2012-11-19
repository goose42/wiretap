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
	number_of_ip_packets = 0;
	number_of_tcp_packets = 0;
	} 

void pcap_data_holder::output_content()
{  
	typedef std::map<string,int>::const_iterator map_iter;
	typedef std::map<int,int>::const_iterator map_iter_int;
	typedef std::map<string, unsigned int>::const_iterator map_iter_string;
	typedef std::map<string, int>::const_iterator map_iter_string_int;
	typedef std::map<string, string >::const_iterator map_iter_string_string;
	typedef std::map<unsigned short,int>::const_iterator map_iter_short;
	
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
	cout<<endl<<"Here are the source IP addresses:"<<endl;	
	cout<<endl<<"Addresses | Number of occurences | %"<<endl<<endl;
	for (map_iter imap = nw_src_ip.begin(); imap != nw_src_ip.end(); imap++)
	{
		cout<<setw(16)<<imap->first<<" -- "<<setw(4)<<imap->second<<" -- "<<std::setprecision(2)<<(((float)imap->second / number_of_ip_packets) * 100)<<"%"<<endl;

	}
	cout<<endl<<"Here are the destination IP addresses:"<<endl;	
	cout<<endl<<"Addresses | Number of occurences | %"<<endl<<endl;
	for (map_iter imap = nw_dest_ip.begin(); imap != nw_dest_ip.end(); imap++)
	{
		cout<<setw(16)<<imap->first<<" -- "<<setw(4)<<imap->second<<" -- "<<std::setprecision(2)<<(((float)imap->second / (float)number_of_ip_packets) * 100)<<"%"<<endl;

	}

	cout<<endl<<"Here are the TTLs found in these IP headers:"<<endl;	
	cout<<endl<<"TTL | Number of occurences | %"<<endl<<endl;
	for (map_iter_int imap = nw_ttl.begin(); imap != nw_ttl.end(); imap++)
	{
		cout<<setw(6)<<imap->first<<" -- "<<setw(4)<<imap->second<<" -- "<<std::setprecision(2)<<(((float)imap->second / (float)number_of_ip_packets) * 100)<<"%"<<endl;

	}

	cout<<endl<<"Here are the ARP participants:"<<endl;	
	cout<<endl<<"MAC address | IP address"<<endl<<endl;
	for (map_iter_string_string imap = nw_arp.begin(); imap != nw_arp.end(); imap++)
	{
		cout<<setw(20)<<imap->first<<" -- "<<setw(16)<<std::dec<<imap->second<<endl;

	}
	cout<<endl<<"********Transport Layer information ******"<<endl<<endl;
	cout<<endl<<"Here are the transport layer protocols:"<<endl;	
	for (map_iter imap = tr_proto.begin(); imap != tr_proto.end(); imap++)
	{
		cout<<setw(6)<<std::hex<<imap->first<<" -- "<<setw(4)<<std::dec<<imap->second<<" -- "<<std::setprecision(2)<<(((float)imap->second / number_of_ip_packets) * 100)<<"%"<<endl;

	}
	cout<<endl<<"TCP information:"<<endl;
	cout<<endl<<"Here are the source port numbers :"<<endl;	
	cout<<endl<<"Port | Number of occurences | %"<<endl<<endl;
	for (map_iter_int imap = tcp_srcports.begin(); imap != tcp_srcports.end(); imap++)
	{
		cout<<std::dec<<setw(6)<<imap->first<<" -- "<<setw(4)<<imap->second<<" -- "<<std::setprecision(2)<<(((float)imap->second / (float)number_of_tcp_packets) * 100)<<"%"<<endl;

	}
	cout<<endl<<"Here are the destinaion port numbers :"<<endl;	
	cout<<endl<<"Port | Number of occurences | %"<<endl<<endl;
	for (map_iter_int imap = tcp_desports.begin(); imap != tcp_desports.end(); imap++)
	{
		cout<<setw(6)<<imap->first<<" -- "<<setw(4)<<imap->second<<" -- "<<std::setprecision(2)<<(((float)imap->second / (float)number_of_tcp_packets) * 100)<<"%"<<endl;

	}
	cout<<endl<<"Here are the TCP flags:"<<endl;	
	cout<<endl<<setw(50)<<"Flags in a given packet | occurences | %"<<endl<<endl;
	for (map_iter_string_int imap = tcp_flags.begin(); imap != tcp_flags.end(); imap++)
	{
		cout<<setw(33)<<imap->first<<" -- "<<setw(6)<<imap->second<<" -- "<<std::setprecision(2)<<(((float)imap->second / (float)number_of_tcp_packets) * 100)<<"%"<<endl;

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
	return;	
}

void pcap_data_holder::add_source_ip(char *src)
{
	number_of_ip_packets++;
	nw_src_ip[src]++;
	return;
	}

	
void pcap_data_holder::add_dest_ip(char *src)
{ 
	nw_dest_ip[src]++;
	return;
	}

	
void pcap_data_holder::add_ttl(short unsigned int ttl)
{
	nw_ttl[ttl]++;
	return;
	}


	
void pcap_data_holder::add_arp_participants(string* arp_mac, string* arp_ip)
{
	nw_arp[*arp_mac] = *arp_ip;
	
	}


void pcap_data_holder::add_transport_protocol(u_int8_t *proto)
{
	switch (*proto)
	{
		case 0x06:
			tr_proto["TCP"]++;
			break;
		case 0x01:
			tr_proto["ICMP"]++;
			break;
		case 0x11:
			tr_proto["UDP"]++;
			break;
		default:
			std::stringstream temp;
			temp<<"0x"<<std::setfill('0')<<setw(2)<<std::hex<<(int)*proto;
			tr_proto[temp.str()]++;
	}

}

void pcap_data_holder::add_tcp_ports(int src_port, int dest_port)
{
	tcp_srcports[src_port]++;
	tcp_desports[dest_port]++;
	number_of_tcp_packets++;
	}

void pcap_data_holder::add_tcp_flags(string flags)
{
	tcp_flags[flags]++;
	
	}	
