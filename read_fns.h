#ifndef _read_fns_h
#define _read_fns_h

#include <pcap/pcap.h>

namespace cap_file
{

	void got_packet(u_char* , const struct pcap_pkthdr* , const u_char* );
	void pcap_read (FILE *);

}

#endif
