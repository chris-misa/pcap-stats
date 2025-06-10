.PHONY: all
all: pcap_stats first_n_packets


pcap_stats: pcap_stats.cpp
	g++ -std=c++17 -Wall -O3 -g $< -o $@ -lpcap

first_n_packets: first_n_packets.cpp
	g++ -std=c++17 -Wall -O3 -g $< -o $@ -lpcap


.PHONY: clean
clean:
	rm -f pcap_stats first_n_packets
