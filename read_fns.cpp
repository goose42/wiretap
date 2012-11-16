#include <iostream>
#include <iomanip>
#include <sstream>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>




#include "read_fns.h"
#include "aggr_packets.h"
#include "net_structures.h"


using std::cout;
using std::endl;
using cap_file::pcap_data_holder;
using std::string;


void cap_file::pcap_read (FILE *fp)
{ 

	pcap_data_holder aggr_packet;	//create an object that will store all the data that we process from the file



	//variables for pcap
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int che_datalink= 0;
	u_char *user_data = (u_char*) &aggr_packet;


	//set up pcap variables
	handle = pcap_fopen_offline(fp,errbuf);
	if (handle == NULL) //error check on creating a handle
	{
		cout<<"Error with pcap_fopen:"<<endl<<errbuf<<endl;
		return;
	}
	che_datalink = pcap_datalink(handle);//check if the file is legit (che_datalink should be 1 for ethernet)
	if (che_datalink == 0)
	{ 
		cout<<"Error with file, please ensure that it is a valid pcap save file :"<<che_datalink<<endl;
		return;
	}


	//read the file for packets here
	pcap_loop(handle, -1, cap_file::got_packet, user_data); 	

	aggr_packet.output_content();
	return;

}  


void cap_file::got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{   
	struct eth *ether = (struct eth *) packet;
	string MAC_src, MAC_dest;

	pcap_data_holder *aggr_data = (pcap_data_holder *) args;

	aggr_data->inc_num_of_pac();

	//linked layer
	MAC_src=cap_file::MAC_in_string(ether->e_src);
	MAC_dest=cap_file::MAC_in_string(ether->e_dest);
	aggr_data->add_MAC(&MAC_src,&MAC_dest);

	//	cout<<std::hex<<ntohs(ether->type)<<endl;

	aggr_data->add_network_protocol(ntohs(ether->type));
	//network later
	if (ntohs(ether->type) == 2048) //do IP related stuff
	{
		struct ip *ip_head = (struct ip *) (packet + sizeof (struct eth));
		aggr_data->add_source_ip(inet_ntoa(ip_head->ip_src));
		aggr_data->add_dest_ip(inet_ntoa(ip_head->ip_dst));
		aggr_data->add_ttl(ip_head->ip_ttl);
		
		//transport layer
		if(ip_head->ip_p == 0x06)
		{
			cout<<"tcp!";
			}

	} 
	
/*	if (ntohs(ether->type) == 2054) //do arp related stuff
	{
		struct arp * arp_head = (struct  arp *) (packet + sizeof (struct eth));
		string arp_mac, arp_ip;
		arp_mac = cap_file::MAC_in_string(arp_head->arp_eth_source);
		//arp_ip = inet_ntoa(arp_head->arp_ip_source);
		aggr_data->add_arp_participants(&arp_mac, arp_head->arp_ip_source); 
		}
	*/
	
	return;
}


string cap_file::MAC_in_string(u_char *raw)
{
	std::stringstream MAC_addr;
	int temp;
	for (int i = 0; i<6; i++)
	{
		temp = (int) raw[i];
		MAC_addr<<std::hex<<std::setw(2)<<std::setfill('0')<<temp;
		if (i < 5)
			MAC_addr<<':';	
		}
		
	return MAC_addr.str();		
	
	} 
