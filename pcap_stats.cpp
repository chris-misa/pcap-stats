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
  0.10,
  0.15,
  0.20,
  0.25,
  0.30,
  0.35,
  0.40,
  0.45,
  0.50,
  0.55,
  0.60,
  0.65,
  0.70,
  0.75,
  0.80,
  0.85,
  0.90,
  0.95,
  0.99,
  0.999,
  1.00
};
const std::vector<std::string> qs_labels = {
  "q000",
  "q005",
  "q010",
  "q015",
  "q020",
  "q025",
  "q030",
  "q035",
  "q040",
  "q045",
  "q050",
  "q055",
  "q060",
  "q065",
  "q070",
  "q075",
  "q080",
  "q085",
  "q090",
  "q095",
  "q099",
  "q0999",
  "q100"
};
const size_t nqs = qs.size();

const std::vector<double> ns = {
  0.001,
  0.01,
  0.05,
  0.10
};
const std::vector<std::string> ns_labels = {
  "Top0.1Percent",
  "Top1Percent",
  "Top5Percent",
  "Top10Percent"
};
const size_t num_ns = ns.size();

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

  flowmap_t **prev_topn;

  uint64_t total_pkts;
  uint64_t total_bytes;
  uint64_t total_skipped;

  state_t() {
    current_flows = new flowmap_t;
    previous_flows = new flowmap_t;

    prev_topn = new flowmap_t*[num_ns];
    for (size_t i = 0; i < num_ns; i++) {
      prev_topn[i] = new flowmap_t;
    }

    total_pkts = 0;
    total_bytes = 0;
    total_skipped = 0;
  }

  ~state_t() {
    delete current_flows;
    delete previous_flows;

    for (size_t i = 0; i < num_ns; i++) {
      delete prev_topn[i];
    }
    delete prev_topn;
  }

  // Update internal state for a single packet
  void one_packet(const std::string &key, const uint64_t bytes) {
    (*current_flows)[key].pkts++;
    (*current_flows)[key].bytes += bytes;

    total_pkts++;
    total_bytes += bytes;
  }

  // Register skipping of a packet
  void skip_one() {
    total_skipped++;
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

    if (n > 0) {
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
    }

    double topn_churn[num_ns];
    for (size_t i = 0; i < num_ns; i++) {
      flowvector_t topn_vec (temp.end() - (size_t)((double)n * ns[i]), temp.end());
      flowmap_t *topn = new flowmap_t (topn_vec.begin(), topn_vec.end());
      topn_churn[i] = get_churn(prev_topn[i], topn);
      delete prev_topn[i];
      prev_topn[i] = topn;
    }

    double churnGlobal = get_churn(previous_flows, current_flows);

    outfile << time << "," << "numFlows" << "," << n << std::endl;
    outfile << time << "," << "totalPkts" << "," << total_pkts << std::endl;
    outfile << time << "," << "totalBytes" << "," << total_bytes << std::endl;
    for (size_t i = 0; i < nqs; i++) {
      outfile << time << "," << qs_labels[i] << "pkts"  << "," << pktsQuants[i].pkts << std::endl;
      outfile << time << "," << qs_labels[i] << "bytes" << "," << bytesQuants[i].bytes << std::endl;
    }
    outfile << time << "," << "churnGlobal" << "," << churnGlobal << std::endl;
    for (size_t i = 0; i < num_ns; i++) {
      outfile << time << "," << "churn" << ns_labels[i] << "," << topn_churn[i] << std::endl;
    }
  }

  // Reset internal state for start of new epoch
  void next_epoch() {
    delete previous_flows;
    previous_flows = current_flows;
    current_flows = new flowmap_t;

    total_pkts = 0;
    total_bytes = 0;
    total_skipped = 0;
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
  int dlt = 0;

  // Open the pcap file
  handle = pcap_open_offline(infile_name, err);
  if (handle == NULL) {
    fprintf(stderr, "Failed to open \"%s\" for reading: %s\n",
      infile_name, err);
    return 1;
  }

  // Check the link type of the opened capture file
  dlt = pcap_datalink(handle);
  if (dlt != DLT_EN10MB &&
      dlt != DLT_RAW) {
    fprintf(stderr, "Unsupported link-layer type: %d\n", dlt);
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
    parse_headers(dlt == DLT_EN10MB, (unsigned char *)pkt, (unsigned char *)(pkt + pcap_hdr.caplen), &hdrs);

    if (hdrs.flags & HEADERS_FLAGS_IPv4 &&
        (hdrs.flags & HEADERS_FLAGS_TCP || hdrs.flags & HEADERS_FLAGS_UDP)) {
      key_str = key_to_string(&hdrs);
      state.one_packet(key_str, hdrs.ipv4->tot_len);
    } else {
      state.skip_one();
    }
  }
  pcap_close(handle);

  // Dump final epoch
  state.dump(outfile, next_epoch);

  // Cleanup
  outfile.close();

  return 0;
}
