.PHONY: all
all: pcap_stats


pcap_stats: pcap_stats.cpp
	g++ -std=c++17 -Wall -O3 -g $< -o $@ -lpcap

.PHONY: clean
clean:
	rm -f pcap_stats
