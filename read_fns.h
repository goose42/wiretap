#ifndef _read_fns_h
#define _read_fns_h

#include <pcap/pcap.h>
#include <string>

#include "net_structures.h"
#include "aggr_packets.h"
namespace cap_file
{  
	void got_packet(u_char* , const struct pcap_pkthdr* , const u_char* );
	void pcap_read (FILE *);
	void get_tcp_options(const u_char *,struct cap_file::tcp_header*, cap_file::pcap_data_holder *);
	std::string MAC_in_string(u_char *);
	std::string get_list_of_TCP_flags(u_char);

}
#endif
