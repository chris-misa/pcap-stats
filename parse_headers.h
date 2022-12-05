#ifndef PARSE_HEADERS_H
#define PARSE_HEADERS_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>

/*********************************
 * Parsing
 *********************************/

/*
 * Flags to keep track of which layers are valid
 */
#define HEADERS_FLAGS_ETH  (1<<0)
#define HEADERS_FLAGS_IPv4 (1<<1)
#define HEADERS_FLAGS_TCP  (1<<2)
#define HEADERS_FLAGS_UDP  (1<<3)

struct headers {
  int flags;
  struct ethhdr *eth;
  struct iphdr *ipv4;
  union {
    struct tcphdr *tcp;
    struct udphdr *udp;
  };
};

static __always_inline unsigned char *
parse_ether(unsigned char *data_start, unsigned char *data_end, struct headers *headers)
{
  struct ethhdr *eth = (struct ethhdr *)data_start;
  int size = sizeof(*eth);

  if (data_start + size <= data_end) {
    headers->eth = eth;
    headers->flags |= HEADERS_FLAGS_ETH;
    return data_start + size;
  }
  return NULL;
}

static __always_inline unsigned char *
parse_ipv4(unsigned char *data_start, unsigned char *data_end, struct headers *headers)
{
  struct iphdr *ip = (struct iphdr *)data_start;
  int size = sizeof(*ip);

  if (ip->version == 4 && data_start + size <= data_end) {
    headers->ipv4 = ip;
    headers->flags |= HEADERS_FLAGS_IPv4;
    return data_start + ip->ihl * 4;
  }
  return NULL;
}

static __always_inline unsigned char *
parse_tcp(unsigned char *data_start, unsigned char *data_end, struct headers *headers)
{
  struct tcphdr *tcp = (struct tcphdr *)data_start;
  int size = sizeof(*tcp);

  if (data_start + size <= data_end) {
    headers->tcp = tcp;
    headers->flags |= HEADERS_FLAGS_TCP;
    return data_start + size;
  }
  return NULL;
}

static __always_inline unsigned char *
parse_udp(unsigned char *data_start, unsigned char *data_end, struct headers *headers)
{
  struct udphdr *udp = (struct udphdr *)data_start;
  int size = sizeof(*udp);

  if (data_start + size <= data_end) {
    headers->udp = udp;
    headers->flags |= HEADERS_FLAGS_UDP;
    return data_start + size;
  }
  return NULL;
}

/*
 * Parse headers in the given buffer
 * Assumes headers is already allocated
 */
static __always_inline unsigned char *
parse_headers(bool hasEther, unsigned char *data_start, unsigned char *data_end, struct headers *headers)
{
  unsigned char *cur;

  if (hasEther) {
      cur = parse_ether(data_start, data_end, headers);
      if (ntohs(headers->eth->h_proto) != ETH_P_IP) {
        cur = NULL;
      }
  } else {
    cur = data_start;
  }

  if (cur != NULL) {
    cur = parse_ipv4(cur, data_end, headers);
    if (cur != NULL) {
      if (headers->ipv4->protocol == IPPROTO_TCP) {
        cur = parse_tcp(cur, data_end, headers);
      } else if (headers->ipv4->protocol == IPPROTO_UDP) {
        cur = parse_udp(cur, data_end, headers);
      }
    }
  }

  return cur;
}
#endif
