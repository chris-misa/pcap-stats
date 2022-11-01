/*
 * Simple utility to read a pcap file and report per-flow packet and bytes coutns
 * Depends on libpcap (on Ubuntu install libpcap-dev)
 */

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <arpa/inet.h>

#include <pcap/pcap.h>

#include "parse_headers.h"

#define KEY_STR_BUF_SIZE 1024

struct flow_state {
  uint32_t pkts;
  uint64_t bytes;
};

using state_t = std::unordered_map<std::string, struct flow_state>;

void
usage(int argc, char *argv[])
{
  printf("Usage: %s <input pcap file> <output csv file>\n", argv[0]);
}

std::string
key_to_string(struct headers *hdrs)
{
  char key_str[KEY_STR_BUF_SIZE] = { 0 };
  char sip_str[INET_ADDRSTRLEN] = { 0 };
  char dip_str[INET_ADDRSTRLEN] = { 0 };
  inet_ntop(AF_INET, &hdrs->ipv4->saddr, sip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &hdrs->ipv4->daddr, dip_str, INET_ADDRSTRLEN);

  snprintf(key_str, KEY_STR_BUF_SIZE, "%s-%s-%u-%u-%u",
    sip_str, dip_str, hdrs->ipv4->protocol, ntohs(hdrs->udp->source), ntohs(hdrs->udp->dest));
  return std::string(key_str);
}

void
dump_header(std::ofstream &outfile)
{
  outfile << "time,stat,pkts,bytes" << std::endl;
}

void
dump_state(std::ofstream &outfile, state_t &state, double time)
{
  std::vector<std::pair<std::string, struct flow_state>> temp (state.begin(), state.end());
  size_t n = temp.size();

  auto m = temp.begin() + (size_t)((double)n * 0.5);
  std::nth_element(temp.begin(), m, temp.end(), [](auto l, auto r) {return l.second.pkts < r.second.pkts; });

  outfile << time << "," << "q0.50" << "," << (*m).second.pkts << "," << (*m).second.bytes << std::endl;
}

int
main(int argc, char *argv[])
{
  if (argc != 3) {
    usage(argc, argv);
    return 0;
  }
  char *infile_name = argv[1];
  char *outfile_name = argv[2];
  char err[PCAP_ERRBUF_SIZE];
  const unsigned char *pkt;
  struct pcap_pkthdr pcap_hdr;
  struct headers hdrs = { 0 };
  std::string key_str;
  std::ofstream outfile;
  state_t flow_table;
  pcap_t *handle;
  double cur_time = 0.0;
  double next_epoch = 0.0;
  double epoch_dur = 1.0;

  // Open the pcap file
  handle = pcap_open_offline(infile_name, err);
  if (handle == NULL) {
    fprintf(stderr, "Failed to open \"%s\" for reading: %s\n",
      infile_name, err);
    return 1;
  }

  // Open the output file
  outfile.open(outfile_name);
  if (!outfile.is_open()) {
    fprintf(stderr, "Failed to open \"%s\" for writing\n",
        outfile_name);
    return 1;
  }
  outfile.setf(std::ios::fixed);
  dump_header(outfile);

  // Process all packets
  while ((pkt = pcap_next(handle, &pcap_hdr)) != NULL) {

    // Handle epoch boundaries
    cur_time = pcap_hdr.ts.tv_sec + (double)pcap_hdr.ts.tv_usec / 1000000.0;
    if (next_epoch == 0.0) {
      next_epoch = cur_time + epoch_dur;
    } else if (cur_time >= next_epoch) {

      // Dump results from previous epoch
      dump_state(outfile, flow_table, next_epoch);
      flow_table.clear();

      // Advance next_epoch
      while (cur_time >= next_epoch) {
        next_epoch += epoch_dur;
      }
    }

    // Process this packet
    parse_headers((unsigned char *)pkt, (unsigned char *)(pkt + pcap_hdr.caplen), &hdrs);
    key_str = key_to_string(&hdrs);

    flow_table[key_str].pkts++;
    flow_table[key_str].bytes += hdrs.ipv4->tot_len;
  }
  pcap_close(handle);

  // Dump final epoch
  dump_state(outfile, flow_table, next_epoch);

  // Cleanup
  outfile.close();

  return 0;
}

