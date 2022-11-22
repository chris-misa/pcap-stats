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

const std::vector<double> qs = {
  0.00,
  0.05,
  0.25,
  0.50,
  0.75,
  0.95,
  1.00
};
const std::vector<std::string> qs_labels = {
  "q000",
  "q005",
  "q025",
  "q050",
  "q075",
  "q095",
  "q100"
};
const size_t nqs = qs.size();

using flowmap_t = std::unordered_map<std::string, flow_state_t>;
using flowvector_t = std::vector<std::pair<std::string, flow_state_t>>;

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

  flowmap_t *prev_top1P;
  flowmap_t *prev_top10P;

  uint64_t total_pkts;
  uint64_t total_bytes;

  state_t() {
    current_flows = new flowmap_t;
    previous_flows = new flowmap_t;

    prev_top1P = new flowmap_t;
    prev_top10P = new flowmap_t;

    total_pkts = 0;
    total_bytes = 0;
  }

  ~state_t() {
    delete current_flows;
    delete previous_flows;

    delete prev_top1P;
    delete prev_top10P;
  }

  void one_packet(const std::string &key, const uint64_t bytes) {
    (*current_flows)[key].pkts++;
    (*current_flows)[key].bytes += bytes;

    total_pkts++;
    total_bytes += bytes;
  }

  void
  dump_header(std::ofstream &outfile) {
    outfile << "time,stat,value" << std::endl;
  }

  // Compute stats and dump
  void dump(std::ofstream &outfile, const double time) {
    flow_state_t pktsQuants[nqs];
    flow_state_t bytesQuants[nqs];

    flowvector_t temp ((*current_flows).begin(), (*current_flows).end());
    size_t n = temp.size();
    size_t idx;

    std::sort(temp.begin(), temp.end(), [](auto l, auto r) { return l.second.bytes < r.second.bytes; });
    for (size_t i = 0; i < nqs; i++) {
      idx = (size_t)((double)n * qs[i]);
      if (idx >= n) { idx = n - 1; } // so we can still use 1.00 in qs
      bytesQuants[i] = temp[idx].second;
    }

    std::sort(temp.begin(), temp.end(), [](auto l, auto r) { return l.second.pkts < r.second.pkts; });
    for (size_t i = 0; i < nqs; i++) {
      idx = (size_t)((double)n * qs[i]);
      if (idx >= n) { idx = n - 1; } // so we can still use 1.00 in qs
      pktsQuants[i] = temp[idx].second;
    }
    flowvector_t top1Pv (temp.end() - (size_t)((double)n * 0.01), temp.end());
    flowmap_t   *top1P = new flowmap_t (top1Pv.begin(), top1Pv.end());
    flowvector_t top10Pv (temp.end() - (size_t)((double)n * 0.1), temp.end());
    flowmap_t   *top10P = new flowmap_t (top10Pv.begin(), top10Pv.end());

    double churnGlobal = get_churn(previous_flows, current_flows);
    double churn1P = get_churn(prev_top1P, top1P);
    double churn10P = get_churn(prev_top10P, top10P);

    delete prev_top1P;
    delete prev_top10P;

    prev_top1P = top1P;
    prev_top10P = top10P;

    outfile << time << "," << "numFlows" << "," << n << std::endl;
    outfile << time << "," << "totalPkts" << "," << total_pkts << std::endl;
    outfile << time << "," << "totalBytes" << "," << total_bytes << std::endl;
    for (size_t i = 0; i < nqs; i++) {
      outfile << time << "," << qs_labels[i] << "pkts"  << "," << pktsQuants[i].pkts << std::endl;
      outfile << time << "," << qs_labels[i] << "bytes" << "," << bytesQuants[i].bytes << std::endl;
    }
    outfile << time << "," << "churnGlobal" << "," << churnGlobal << std::endl;
    outfile << time << "," << "churnTop1Percent" << "," << churn1P << std::endl;
    outfile << time << "," << "churnTop10Percent" << "," << churn10P << std::endl;
  }

  void next_epoch() {
    delete previous_flows;
    previous_flows = current_flows;
    current_flows = new flowmap_t;

    total_pkts = 0;
    total_bytes = 0;
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

