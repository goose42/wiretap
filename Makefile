SOURCES=wiretap.cpp process_pcap_file.h process_pcap_file.cpp

OUTPUT=wiretap
CC=g++
CFLAGS=-g -Wall
test_input=traceroute.pcap


$(OUTPUT): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -lpcap -o $(OUTPUT)  


run: $(OUTPUT)
	./$< $(test_input)


