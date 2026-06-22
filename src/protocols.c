
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
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


  uint8_t header_length = packet[offset] & 0b00001111;
  LOG_PRINT("HL: %u\n", header_length);

  pkt->addrs.ipv4.src_ip = *(uint32_t *)(packet + offset + IPV4_SRC_ADDRESS_OFFSET);
  pkt->addrs.ipv4.dst_ip = *(uint32_t *)(packet + offset + IPV4_DST_ADDRESS_OFFSET);

  pkt->proto = packet[offset + IPV4_PROTOCOL_OFFSET];

  return pkt->proto;
}


// Assumption: [len] > [ETHERNET_ETHERTYPE_OFFSET]
uint32_t findVlanOffset(const uint8_t *packet, uint32_t len) {
  assert(len > ETHERNET_ETHERTYPE_OFFSET);
  uint16_t type = ntohs(*(uint16_t *)(packet + ETHERNET_ETHERTYPE_OFFSET));
  switch (type) {
    case VLAN_TAG:
      return VLAN_HEADER_SIZE;
    case DOUBLE_VLAN_TAG:
      return VLAN_HEADER_SIZE * 2;
    default:
      return 0;
  }
}

void *parse_protocols(void *args) {
  const XDPPacketWrapper *data = args;
  struct Packet *packet = malloc(sizeof(*packet));

  uint32_t vlan_offset = findVlanOffset(data->packet, data->length);
  packet->type = ntohs(*(uint16_t *)(data->packet + vlan_offset + ETHERNET_ETHERTYPE_OFFSET));


  if (vlan_offset + ETHERNET_HEADER_SIZE > data->length) {
    LOG_PRINT("vlan_offset(%u) + ETHERNET_HEADER_SIZE(%u) > data->length(%u)\n", vlan_offset, ETHERNET_HEADER_SIZE, data->length);
    free(packet);
    return nullptr;
  }

  switch (packet->type) {
    case PROTOCOL_IPV4:
      packet->proto = parseIPv4(data->packet, data->length - vlan_offset - ETHERNET_HEADER_SIZE, vlan_offset + ETHERNET_HEADER_SIZE, packet);
      char src_buffer[INET_ADDRSTRLEN + 1];
      char dst_buffer[INET_ADDRSTRLEN + 1];
      
      inet_ntop(AF_INET, &packet->addrs.ipv4.src_ip, src_buffer, sizeof(src_buffer) - 1);
      inet_ntop(AF_INET, &packet->addrs.ipv4.dst_ip, dst_buffer, sizeof(dst_buffer) - 1);
      LOG_PRINT("Protocol: 0x%02x/0x%04x (%s/IPv4): %s -> %s\n", packet->proto, packet->type, getL3ProtocolName(packet->proto), src_buffer, dst_buffer);
      break;
    case PROTOCOL_IPV6:
      packet->proto = parseIPv6(data->packet, data->length - vlan_offset - ETHERNET_HEADER_SIZE, vlan_offset + ETHERNET_HEADER_SIZE, packet);
      LOG_PRINT("Protocol: 0x%02x/0x%04x (%s/IPv6)\n", packet->proto, packet->type, getL3ProtocolName(packet->proto));
      break;
    case PROTOCOL_ARP:
      LOG_PRINT("Protocol: 0x0806 (ARP)\n");
      break;
    default:
      LOG_PRINT("Protocol: 0x%04x (UNKNOWN)", packet->type);
      break;
  }

  return packet;
}
