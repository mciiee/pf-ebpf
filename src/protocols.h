#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <linux/bpf.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>

#define ETHERNET_PROTOCOL_OFFSET 12

typedef __u8 u8;
typedef __u16 u16;

enum L3Protocol: u8 {
  PROCOTOL_UNKNOWN = 0x0,
  PROTOCOL_ICMP = 0x1,
  PROTOCOL_IGMP = 0x2,
  PROCOTOL_TCP = 0x6,
  PROTOCOL_UDP = 0x11,
  PROTOCOL_OSPF = 0x59,
  PROTOCOL_SCTP = 0x84,
  PROTOCOL_ICMPv6 = 0x3a,
};

enum L2Protocol: u16 {
  PROTOCOL_UNKNOWN = 0x0,
  PROTOCOL_IPV4 = 0x0800,
  PROTOCOL_IPV6 = 0x86dd,
  PROTOCOL_ARP = 0x0806,
  VLAN_TAG = 0x8100, 
};

struct ArpPacket {
  u8 *payload;
};

struct IPv4Addresses {
  uint32_t src_ip;
  uint32_t dst_ip;
};

struct IPv6Addresses {
  struct in6_addr src_ip;
  struct in6_addr dst_ip;
};

union Addresses {
  struct IPv4Addresses ipv4;
  struct IPv6Addresses ipv6;
};

struct Packet {
  atomic_bool free;
  enum L3Protocol proto;
  enum L2Protocol type;
  union Addresses addrs;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t payload[];
};

#endif
