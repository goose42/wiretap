#ifndef _read_fns_h
#define _read_fns_h

#include <pcap/pcap.h>
#include <string>

namespace cap_file
{ 
	void got_packet(u_char* , const struct pcap_pkthdr* , const u_char* );
	void pcap_read (FILE *);
	std::string MAC_in_string(u_char *);
	std::string get_list_of_TCP_flags(u_char);

}
#endif
