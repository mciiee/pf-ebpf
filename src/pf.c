#ifndef asm 
#define asm __asm__
#endif

#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#include "protocols.h"

#define ETHERNET_ETHERTYPE_OFFSET 12
#define ETHERNET_ETHERTYPE_OFFSET_VLAN 16
#define ETHERNET_HEADER_SIZE 14
#define IPV6_NEXT_HEADER_OFFSET 6
#define IPV4_PROTOCOL_OFFSET 9




// L3 by TCP/IP. L4 by OSI
[[unsequenced]]
static inline char *getL3ProtocolName(enum L3Protocol proto){
  //bpf_printk("[DEBUG] proto: 0x%02x", proto);
  switch (proto) {
    case PROTOCOL_ICMP:
      return "ICMPv4";
    case PROTOCOL_IGMP:
      return "IGMP";
    case PROCOTOL_TCP:
      return "TCP";
    case PROTOCOL_UDP:
      return "UDP";
    case PROTOCOL_OSPF:
      return "OSPF";
    case PROTOCOL_SCTP:
      return "SCTP";
    case PROTOCOL_ICMPv6:
      return "ICMPv6";
    default:
      return "UNKNOWN";
  }
}

// L2 by TCP/IP. L3 by OSI
[[unsequenced]]
static inline char *getL2ProtocolName(enum L2Protocol proto){
  switch (proto) {
    //case PROTOCOL_UNKNOWN:
    case PROTOCOL_IPV4:
      return "IPv4";
    case PROTOCOL_IPV6:
      return "IPv6";
    case PROTOCOL_ARP:
      return "ARP";
    default:
      return "UNKNOWN";
    }
}

static int inline parseIPv6(const struct xdp_md *ctx){
  if (ctx->data + (ETHERNET_HEADER_SIZE + IPV6_NEXT_HEADER_OFFSET) * sizeof(u8) >= ctx->data_end) {
    return PROTOCOL_UNKNOWN;
  }
  enum L3Protocol proto = ((u8*)(long)ctx->data)[ETHERNET_HEADER_SIZE + IPV6_NEXT_HEADER_OFFSET];
  return proto;
}

static int inline parseIPv4(const struct xdp_md *ctx) {
  if (ctx->data + (ETHERNET_HEADER_SIZE + IPV4_PROTOCOL_OFFSET) * sizeof(u8) >= ctx->data_end) {
    return PROTOCOL_UNKNOWN;
  }
  enum L3Protocol proto = ((u8*)(long)ctx->data)[ETHERNET_HEADER_SIZE + IPV4_PROTOCOL_OFFSET];
  return proto;
}

static inline u16 u16Byteswap(const u16 num) {
  return (*(u8*)&num) * (1 << 8) + *((u8*)&num + 1);
}

SEC("xdp")
int xdp_pf(struct xdp_md *ctx)
{
  u8 *data = (u8 *)(long)ctx->data;
  u8 *data_end = (u8 *)(long)ctx->data_end;
  //int pkt_sz = data_end - data;
  //bpf_printk("packet size is %d", pkt_sz);

  if ((u16*)(data + ETHERNET_HEADER_SIZE * sizeof(u8)) > (u16*)data_end) {
    bpf_printk("Invalid packet: packet size <= ETHERNET_HEADER_SIZE");
    return XDP_PASS;
  }
  
  enum L2Protocol iproto = u16Byteswap(*(u16*)(data + ETHERNET_ETHERTYPE_OFFSET));
  if (iproto == VLAN_TAG && (u16*)(data + ETHERNET_ETHERTYPE_OFFSET_VLAN + 2) < (u16*)data_end) {
    u16 vlan_id = *(u16*)(data + ETHERNET_ETHERTYPE_OFFSET_VLAN);
    *(u8*)&vlan_id &= 0b00001111;
    bpf_printk("VLAN: %u", vlan_id);
    iproto = u16Byteswap(*(u16*)(data + ETHERNET_ETHERTYPE_OFFSET_VLAN));
  }
  else if (iproto == VLAN_TAG) {
    bpf_printk("Invalid packet: packet size <= ETHERNET_HEADER_SIZE");
    return XDP_PASS;
  }
  enum L3Protocol tproto;

  switch (iproto) {
    case PROTOCOL_IPV4:
      tproto = parseIPv4(ctx);
      bpf_printk("Protocol: 0x%02x/0x%04x (%s/IPv4)", tproto, iproto, getL3ProtocolName(tproto));
      break;
    case PROTOCOL_IPV6:
      tproto = parseIPv6(ctx);
      bpf_printk("Protocol: 0x%02x/0x%04x (%s/IPv6)", tproto, iproto, getL3ProtocolName(tproto));
      break;
    case PROTOCOL_ARP:
      bpf_printk("Protocol: 0x%04x (ARP)", iproto);
      break;
    default: 
      bpf_printk("Protocol: 0x%04x (UNKNOWN)", iproto);
      break;
  }

  

  return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPLv3";

