#include <iostream>
#include <stdio.h>
#include <pcap/pcap.h>


using std::cout;
using std::endl;

int number_of_packets = 0;

void pcap_read (FILE *);

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
//	static int number_of_packets = 0;
//	cout<<"hey we got a packet"<<endl;
	number_of_packets++;
//	cout<<"Total number of packets :"<<number_of_packets<<endl;
	}


int main(int argc,char* argv[])
{
  FILE *input_file;
  
  if (argc != 2) //check if correct number of arguments
  {
    cout<<"Incorrect method to execute wiretap."<<endl<<"Please run wiretap with the following command:"<<endl<<"\t./wiretap <pcap dump file name>"<<endl;
    return 0;
    }
  input_file = fopen(argv[1], "r"); //open file
  
  if (input_file == NULL) //check if file opens correctly.
   {
    cout<<"Error with opening file, please check the file name"<<endl;
    return 0;
    }  
  //once file is opened, pass it into the pcap method to read and make sense of
  pcap_read(input_file); 
   
  return 0;
  }


void pcap_read (FILE *fp)
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
	pcap_loop(handle, -1, got_packet, user_data); 	
	
	cout<<"total number of packets:"<<number_of_packets<<endl;
	return;

	}




