#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <linux/bpf.h>

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

#endif
