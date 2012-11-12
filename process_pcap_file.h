#ifndef _PROCESS_PCAP_FILE_H
#define _PROCESS_PCAP_FILE_H

#include <pcap/pcap.h>
namespace cap_file
{
	static int number_of_packets=0;

	void got_packet(u_char* , const struct pcap_pkthdr* , const u_char* );

	void pcap_read (FILE *);


}


#endif
