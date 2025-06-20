/*
 * Simple utility to read a pcap file and report per-packet features for first n packets of each (five-tuple) flow.
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

/*
  concretely, what per-packet features?

  (iphdr)
  ip.tot_len;
  ip.ttl;
  ip.ptotocol (but this is part of the flow id!)

  (tcphdr)
  .flags (just as integer...)
  .window
  .seq
  .ack_seq
  .source
  .dest
  ... but project out only well-known service number

  (udphdr)
  .source
  .dest
  ... but project out only well-known service numbers
 */

// Note: any updates to pkt_fields_t must be reflected in field_types_str, num_fields, put_fields(), and extract_pkt_fields()
// Maybe add time since last packet?
struct pkt_fields_t {
  uint16_t ip_len;
  uint16_t ip_ttl;
  uint16_t tcp_flags;
  uint16_t tcp_window; // TCP window might be too specific because different impls have different default values (which have nothing to do with the type of traffic...) (unless there's some way to normalize it?)
  double time;

  uint32_t tcp_seq;
  uint32_t tcp_ack_seq;

  pkt_fields_t()
    : ip_len(0),
      ip_ttl(0),
      tcp_flags(0),
      tcp_window(0),
      time(0),
      tcp_seq(0),
      tcp_ack_seq(0) {}
};

// Using fields types from Sharigan / NetQRE implementation
// 0 => numeric (ordered set)
// 1 => set-like (e.g., IP addresses)
// 2 => categorical
std::string field_types_str = std::string("0 0 2 2 2 2 2 2 2 2 0 2 2 2 2 0");

int num_fields = 16;

void
put_fields(std::ofstream &outfile, const struct pkt_fields_t &f, struct pkt_fields_t &prev_f)
{
  // Compute some derived features from the raw values in pkt_fields_t...
  
  int seq_increasing = prev_f.tcp_seq < f.tcp_seq ? 1 : 0;
  int seq_eq = prev_f.tcp_seq == f.tcp_seq ? 1 : 0;
  prev_f.tcp_seq = f.tcp_seq;

  int ack_seq_increasing = prev_f.tcp_ack_seq < f.tcp_ack_seq ? 1 : 0;
  int ack_seq_eq = prev_f.tcp_ack_seq == f.tcp_ack_seq ? 1 : 0;
  prev_f.tcp_ack_seq = f.tcp_ack_seq;

  int tcp_fin = (f.tcp_flags & 0x1) ? 1 : 0;
  int tcp_syn = (f.tcp_flags & 0x2) ? 1 : 0;
  int tcp_rst = (f.tcp_flags & 0x4) ? 1 : 0;
  int tcp_psh = (f.tcp_flags & 0x8) ? 1 : 0;
  int tcp_ack = (f.tcp_flags & 0x10) ? 1 : 0;
  int tcp_urg = (f.tcp_flags & 0x20) ? 1 : 0;
  int tcp_ece = (f.tcp_flags & 0x40) ? 1 : 0;
  int tcp_cwr = (f.tcp_flags & 0x80) ? 1 : 0;

  double dt = prev_f.time != 0.0 ? f.time - prev_f.time : 0.0;
  prev_f.time = f.time;

  outfile
    << f.ip_len << " "
    << f.ip_ttl << " "
    << tcp_fin << " "
    << tcp_syn << " "
    << tcp_rst << " "
    << tcp_psh << " "
    << tcp_ack << " "
    << tcp_urg << " "
    << tcp_ece << " "
    << tcp_cwr << " "
    // << f.tcp_flags << " "
    << f.tcp_window << " "
    << seq_increasing << " "
    << seq_eq << " "
    << ack_seq_increasing << " "
    << ack_seq_eq << " "
    << dt << " "
    << std::endl;
}

using flowmap_t =
  std::unordered_map<std::string, std::vector<pkt_fields_t>>;

void
usage(int argc, char *argv[])
{
  printf("Usage: %s <max packets per flow> <min packets per flow> <input pcap file> <output csv file>\n", argv[0]);
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

// Assumes hdrs has at least valid IPv4 field
pkt_fields_t
extract_pkt_fields(const struct headers &hdrs)
{
  pkt_fields_t fields;
  fields.ip_len = ntohs(hdrs.ipv4->tot_len);
  fields.ip_ttl = (uint16_t)hdrs.ipv4->ttl;

  if (hdrs.flags & HEADERS_FLAGS_TCP) {
    fields.tcp_flags = (tcp_flag_word(hdrs.tcp) >> 8) & 0xFF;
    fields.tcp_window = ntohs(hdrs.tcp->window);

    fields.tcp_seq = ntohl(hdrs.tcp->seq);
    fields.tcp_ack_seq = ntohl(hdrs.tcp->ack_seq);
  }

  
  // TODO: set fields.application_type based on common application port numbers
  return fields;
}

struct state_t {

  flowmap_t *current_flows;
  size_t max_pkts_per_flow;
  size_t min_pkts_per_flow;

  uint64_t total_pkts;
  uint64_t total_skipped;

  state_t(size_t max_pkts_per_flow, size_t min_pkts_per_flow)
    : current_flows(new flowmap_t),
      max_pkts_per_flow(max_pkts_per_flow),
      min_pkts_per_flow(min_pkts_per_flow),
      total_pkts(0),
      total_skipped(0) {}

  ~state_t() {
    delete current_flows;
  }

  // Update internal state for a single packet
  void one_packet(double time, const std::string &key, const struct headers &hdrs) {

    if ((*current_flows)[key].size() < max_pkts_per_flow) {
      pkt_fields_t pkt = extract_pkt_fields(hdrs);
      pkt.time = time;
      (*current_flows)[key].push_back(pkt);
    }

    total_pkts++;
  }

  // Register skipping of a packet
  void skip_one() {
    total_skipped++;
  }

  void dump_header(std::ofstream &outfile) {
    int num_flows = 0;
    for (auto i = (*current_flows).begin(); i != (*current_flows).end(); i++)
      {
        if (i->second.size() >= min_pkts_per_flow) num_flows++;
      }
    
    outfile << num_flows << " " << num_fields << std::endl;
    outfile << field_types_str << std::endl;
  }

  // Compute stats and dump
  void dump(std::ofstream &outfile) {
    for (auto i = (*current_flows).begin(); i != (*current_flows).end(); i++)
      {
        // outfile << i->first << std::endl;
        // i->first is the key
        // i->second is the vector of packets
	pkt_fields_t prev_f = pkt_fields_t();
        if (i->second.size() >= min_pkts_per_flow) {
          for (auto f = i->second.begin(); f != i->second.end(); f++)
            {
              // For debugging, look at flow keys
              // outfile << i->first << ": ";
              put_fields(outfile, *f, prev_f);
            }
          outfile << std::endl; // extra newline delimits sequences
        }
      }
  }
};

int
main(int argc, char *argv[])
{
  if (argc != 5) {
    usage(argc, argv);
    return 0;
  }
  size_t max_pkts_per_flow = (size_t)atoi(argv[1]);
  size_t min_pkts_per_flow = (size_t)atoi(argv[2]);
  char *infile_name = argv[3];
  char *outfile_name = argv[4];
  char err[PCAP_ERRBUF_SIZE];

  const unsigned char *pkt;
  struct pcap_pkthdr pcap_hdr;
  struct headers hdrs = { 0 };
  std::string key_str;
  std::ofstream outfile;
  state_t state(max_pkts_per_flow, min_pkts_per_flow);
  pcap_t *handle;
  int dlt;

  double cur_time = 0.0;

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

  // Process all packets
  while ((pkt = pcap_next(handle, &pcap_hdr)) != NULL) {

    // Handle epoch boundaries
    cur_time = pcap_hdr.ts.tv_sec + (double)pcap_hdr.ts.tv_usec / 1000000.0;

    // Process this packet
    parse_headers(dlt == DLT_EN10MB, (unsigned char *)pkt, (unsigned char *)(pkt + pcap_hdr.caplen), &hdrs);

    if (hdrs.flags & HEADERS_FLAGS_IPv4 &&
        (hdrs.flags & HEADERS_FLAGS_TCP || hdrs.flags & HEADERS_FLAGS_UDP)) {
      key_str = key_to_string(&hdrs);
      state.one_packet(cur_time, key_str, hdrs);
    } else {
      state.skip_one();
    }
  }
  pcap_close(handle);

  state.dump_header(outfile);
  state.dump(outfile);

  // Cleanup
  outfile.close();

  return 0;
}
