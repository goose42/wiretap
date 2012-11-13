SOURCES=wiretap.cpp aggr_packets.h aggr_packets.cpp read_fns.cpp read_fns.h net_structures.h

OUTPUT=wiretap
CC=g++
CFLAGS=-g -Wall
test_input=traceroute.pcap


$(OUTPUT): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -lpcap -o $(OUTPUT)  


run: $(OUTPUT)
	./$< $(test_input)


