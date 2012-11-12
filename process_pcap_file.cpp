#include <iostream>

using std::cout;
using std::endl;

#include "process_pcap_file.h"
void cap_file::got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
//	static int number_of_packets = 0;
//	cout<<"hey we got a packet"<<endl;
	cap_file::number_of_packets++;
//	cout<<"Total number of packets :"<<number_of_packets<<endl;
	}


void cap_file::pcap_read (FILE *fp)
{
  //now here, we set up the logic to read the file and perform a call back when a packet is found.
  
	//variables for pcap
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
  int che_datalink= 0;
	u_char *user_data;
	
	
	
		
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
	
	cout<<"total number of packets:"<<cap_file::number_of_packets<<endl;
	return;

	}


