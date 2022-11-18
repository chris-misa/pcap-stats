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

struct flow_state_t {
  uint32_t pkts;
  uint64_t bytes;

  flow_state_t() {
    pkts = 0;
    bytes = 0;
  }
};

using flowmap_t = std::unordered_map<std::string, struct flow_state_t>;

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

flow_state_t
get_quantile(const flowmap_t *flows, double q)
{
  std::vector<std::pair<std::string, struct flow_state_t>> temp ((*flows).begin(), (*flows).end());
  size_t n = temp.size();

  auto m = temp.begin() + (size_t)((double)n * q);
  std::nth_element(temp.begin(), m, temp.end(), [](auto l, auto r) {return l.second.pkts < r.second.pkts; });
  return (*m).second;
}

double
get_churn(const flowmap_t *prev, const flowmap_t *next)
{
  size_t n = 0;

  for (auto& [key, value] : (*prev)) {
    if (next->find(key) == next->end()) {
      n++;
    }
  }

  return prev->size() != 0 ? (double)n / (double)prev->size() : 0;
}

struct state_t {

  flowmap_t *current_flows;
  flowmap_t *previous_flows;

  state_t() {
    current_flows = new flowmap_t;
    previous_flows = new flowmap_t;
  }

  ~state_t() {
    delete current_flows;
    delete previous_flows;
  }

  void one_packet(const std::string &key, const uint64_t bytes) {
    (*current_flows)[key].pkts++;
    (*current_flows)[key].bytes += bytes;
  }

  void
  dump_header(std::ofstream &outfile) {
    outfile << "time,stat,value" << std::endl;
  }

  void dump(std::ofstream &outfile, const double time) {
    flow_state_t q50 = get_quantile(current_flows, 0.5);
    double churn = get_churn(previous_flows, current_flows);

    outfile << time << "," << "q50pkts" << "," << q50.pkts << std::endl;
    outfile << time << "," << "q50bytes" << "," << q50.bytes << std::endl;
    outfile << time << "," << "churn" << "," << churn << std::endl;
  }

  void next_epoch() {
    delete previous_flows;
    previous_flows = current_flows;
    current_flows = new flowmap_t;
  }
};

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
  state_t state;
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
  state.dump_header(outfile);

  // Process all packets
  while ((pkt = pcap_next(handle, &pcap_hdr)) != NULL) {

    // Handle epoch boundaries
    cur_time = pcap_hdr.ts.tv_sec + (double)pcap_hdr.ts.tv_usec / 1000000.0;
    if (next_epoch == 0.0) {
      next_epoch = cur_time + epoch_dur;
    } else if (cur_time >= next_epoch) {

      // Dump results from previous epoch
      state.dump(outfile, next_epoch);
      state.next_epoch();

      // Advance next_epoch
      while (cur_time >= next_epoch) {
        next_epoch += epoch_dur;
      }
    }

    // Process this packet
    parse_headers((unsigned char *)pkt, (unsigned char *)(pkt + pcap_hdr.caplen), &hdrs);
    key_str = key_to_string(&hdrs);

    state.one_packet(key_str, hdrs.ipv4->tot_len);
  }
  pcap_close(handle);

  // Dump final epoch
  state.dump(outfile, next_epoch);

  // Cleanup
  outfile.close();

  return 0;
}

