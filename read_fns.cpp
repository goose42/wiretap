#include <iostream>
#include <iomanip>
#include <sstream>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <cstdlib>
#include <sys/time.h>


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
	
	//time stuff
	
	



	
	pcap_data_holder *aggr_data = (pcap_data_holder *) args;


	aggr_data->add_packet_size(header->len);
	aggr_data->add_time((long int*) &header->ts.tv_sec,(long int *)&header->ts.tv_usec);
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
		aggr_data->add_transport_protocol(&ip_head->ip_p);
		if(ip_head->ip_p == 0x06) //if we see a tcp protocol, do
		{ 
			struct cap_file::tcp_header *tcp_hdr = (struct cap_file::tcp_header *) (packet + sizeof (struct eth) + sizeof (struct ip));
			int source_tcp_port = ntohs(tcp_hdr->th_sport);
			int dest_tcp_port = ntohs(tcp_hdr->th_dport);
			aggr_data->add_tcp_ports(source_tcp_port,dest_tcp_port);
			
			//get the flags as a list, in a string
			aggr_data->add_tcp_flags(get_list_of_TCP_flags(tcp_hdr->th_flags));	
			//get options
			cap_file::get_tcp_options(packet, tcp_hdr, aggr_data);
			
			}	 
		if(ip_head->ip_p == 0x11)//if we see a UCP protocol, do
		{ 
			struct cap_file::udphdr *udp_header = (struct cap_file::udphdr *) (packet + sizeof (struct eth) + sizeof (struct ip));
			int source_udp_port = ntohs(udp_header->uh_sport);
			int dest_udp_port = ntohs(udp_header->uh_dport);
			aggr_data->add_udp_ports(&source_udp_port,&dest_udp_port);
			}
		if(ip_head->ip_p == 0x01)//if we see an ICMP protocol, do
		{
			struct icmphdr *icmp_hdr = (struct icmphdr *) (packet + sizeof (struct eth) + sizeof (struct ip));

			string src_ip = inet_ntoa(ip_head->ip_src);
			string dst_ip = inet_ntoa(ip_head->ip_dst);
			aggr_data->add_icmp_ip(&src_ip, &dst_ip);
			int code = icmp_hdr->code; 
			aggr_data->add_icmp_code(&code);
			int type = icmp_hdr->type;
			aggr_data->add_icmp_type(&type);
		}

	}  

	if (ntohs(ether->type) == 2054) //do arp related stuff
	{
		struct ether_arp * arp_head = (struct  ether_arp *) (packet + sizeof(struct eth));
		string arp_mac, arp_ip;
		arp_mac = cap_file::MAC_in_string(arp_head->arp_sha);
		arp_ip = inet_ntoa(*(struct in_addr *) arp_head->arp_spa);
		aggr_data->add_arp_participants(&arp_mac, &arp_ip); 
		}
	
	
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
	




void cap_file::get_tcp_options(const u_char *packet,struct cap_file::tcp_header *tcp_head, pcap_data_holder *aggr_data)
{
	char *read_opts;
	int length_trav =0;
	int type;
	std::map <int,int> type_seen;
	std::map <int, int> tcp_opt_len;
	tcp_opt_len[2]=4;
	tcp_opt_len[3]=3;
	tcp_opt_len[4]=2;
	tcp_opt_len[6]=6;
	tcp_opt_len[7]=6;
	tcp_opt_len[8]=10;
	tcp_opt_len[9]=2;
	tcp_opt_len[10]=3;
	tcp_opt_len[14]=3;
	tcp_opt_len[18]=3;
	tcp_opt_len[19]=18;
	tcp_opt_len[27]=8;
	tcp_opt_len[28]=4;	

	//cout<<tcp_head->th_of*4<<endl;
	
	if ((tcp_head->th_of*4) > 20 )

	{
		while (length_trav < (tcp_head->th_of*4) - 20 )	
		{
			read_opts = (char *) (packet + sizeof (struct eth) + sizeof (struct ip)) + 20 + length_trav;
			type =(int)read_opts[0]; 
			if (type_seen.find(type) == type_seen.end())
				aggr_data->add_tcp_opts(type);		
			type_seen[type]++;
			if (tcp_opt_len.find(type) == tcp_opt_len.end())
				length_trav += 1;
			else
				length_trav += tcp_opt_len[type];
		}
	}	
	//cout<<endl;
}

//string ip_uint_to_ip(uint)

string cap_file::get_list_of_TCP_flags(u_char flag_tcp)
{ 
	std::stringstream flag_str;
	bool not_first_flag = false;
	if ((flag_tcp & 0x20) == TH_URG)
 	{
		if (not_first_flag)
		{
			flag_str<<" + ";
		}
		flag_str<<"URG";
		not_first_flag = true;	
	}
	if ((flag_tcp & 0x10) == TH_ACK)
	{ 
		if (not_first_flag)
		{
			flag_str<<" + ";
		}
		flag_str<<"ACK";
		not_first_flag = true;	
	}
	if ((flag_tcp & 0x08) == TH_PUSH)
	{
		if (not_first_flag)
		{
			flag_str<<" + ";
		}
		flag_str<<"PUSH";
		not_first_flag = true;	
	} 
	if ((flag_tcp & 0x04) == TH_RST)
	{
		if (not_first_flag)
		{
			flag_str<<" + ";
		}
		flag_str<<"RST";
		not_first_flag = true;	
	} 
	if ((flag_tcp & 0x02) == TH_SYN)
	{ 
		if (not_first_flag)
		{
			flag_str<<" + ";
		 }
		flag_str<<"SYN";
		not_first_flag = true;	
	}
	if ((flag_tcp & 0x01) == TH_FIN)
	{ 
		if (not_first_flag)
		{
			flag_str<<" + ";
		}
		flag_str<<"FIN";
		not_first_flag = true;	
	}
	return flag_str.str();
} 
