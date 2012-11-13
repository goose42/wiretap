#include <iostream>
#include <iomanip>
#include <sstream>

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

	MAC_src=cap_file::MAC_in_string(ether->e_src);
	MAC_dest=cap_file::MAC_in_string(ether->e_dest);
	aggr_data->add_MAC(&MAC_src,&MAC_dest);


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
