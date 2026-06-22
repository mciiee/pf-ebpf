
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>


#include "EntropyDataWrapper.h"
#include "log.h"
#include "protocols.h"



static inline char *getL3ProtocolName(enum L3Protocol proto) {
  // bpf_printk("[DEBUG] proto: 0x%02x", proto);
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

static inline char *getL2ProtocolName(enum L2Protocol proto) {
  switch (proto) {
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

static inline int parseIPv6(const uint8_t *packet, uint32_t len, uint32_t offset, struct Packet *pkt) {
  enum L3Protocol proto = packet[offset + IPV6_NEXT_HEADER_OFFSET];
  return proto;
}

static inline int parseIPv4(const uint8_t *packet, uint32_t len, uint32_t offset, struct Packet *pkt) {
  enum L3Protocol proto = packet[offset + IPV4_PROTOCOL_OFFSET];
  return proto;
}


void *parse_protocols(void *args) {
  const XDPPacketWrapper *data = args;
  struct Packet *packet = malloc(sizeof(*packet));

  packet->type = ntohs(*(uint16_t *)(data->packet + ETHERNET_ETHERTYPE_OFFSET));
  //LOG_PRINT("LL Protocol: 0x%04X\n", l2proto);
  switch (packet->type) {
    case PROTOCOL_UNKNOWN:
      LOG_PRINT("Protocol: UNKNOWN\n");
      break;
    case PROTOCOL_IPV4:
      packet->proto = parseIPv4(data->packet, data->length, ETHERNET_HEADER_SIZE, packet);
      LOG_PRINT("Protocol: 0x%02x/0x%04x (%s/IPv4)\n", packet->proto, packet->type, getL3ProtocolName(packet->proto));
      break;
    case PROTOCOL_IPV6:
      packet->proto = parseIPv6(data->packet, data->length, ETHERNET_HEADER_SIZE, packet);
      LOG_PRINT("Protocol: 0x%02x/0x%04x (%s/IPv6)\n", packet->proto, packet->type, getL3ProtocolName(packet->proto));
      break;
    case PROTOCOL_ARP:
      LOG_PRINT("Protocol: 0x0806 (ARP)\n");
      break;
    case VLAN_TAG:
      //l2proto = ntohs(*(uint16_t *)(packet + ETHERNET_ETHERTYPE_OFFSET_VLAN));
      LOG_PRINT("Protocol: [UNKNOWN/VLAN]\n");
      break;
    default:
      LOG_PRINT("Protocol: 0x%04x (UNKNOWN)", packet->type);
      break;
  }

  return packet;
}
