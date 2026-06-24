#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "EntropyDataWrapper.h"
#include "log.h"
#include "protocols.h"
#include "mempool.h"

static void dumpPacket(const uint8_t *packet, uint32_t len){
  char buffer[len * 3 + 1];
  buffer[len * 3] = '\0';

  for (uint32_t i = 0; i < len; i++) {
    snprintf(buffer + 3 * i, 4, "%02x ", packet[i]);
  }
  LOG_PRINT("Packet: %s\n", buffer);
}


static inline char *getL3ProtocolName(enum L3Protocol proto) {
  // bpf_printk("[DEBUG] proto: 0x%02x", proto);
  switch (proto) {
    case PROTOCOL_ICMP:
      return "ICMPv4";
    case PROTOCOL_IGMP:
      return "IGMP";
    case PROTOCOL_TCP:
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


static inline int parseUDP(const uint8_t *packet, uint32_t len, uint32_t offset, struct Packet *pkt) {
  assert (offset + UDP_HEADER_SIZE <= len);

  pkt->src_port = htons(*(uint16_t *)(packet + offset + UDP_SRC_PORT_OFFSET));
  pkt->dst_port = htons(*(uint16_t *)(packet + offset + UDP_DST_PORT_OFFSET));
  return 0;
}

static inline int parseTCP(const uint8_t *packet, uint32_t len, volatile uint32_t offset, struct Packet *pkt) {
  assert(offset + TCP_DST_PORT_OFFSET + 2 <= len);

  pkt->src_port = htons(*(uint16_t *)(packet + offset + TCP_SRC_PORT_OFFSET));
  pkt->dst_port = htons(*(uint16_t *)(packet + offset + TCP_DST_PORT_OFFSET));

  return 0;
}

static int parseL3Proto(const uint8_t *packet, uint32_t len, uint32_t offset, struct Packet *pkt){
  switch (pkt->proto) {
  case PROTOCOL_TCP:
    return parseTCP(packet, len, offset, pkt);
  case PROTOCOL_UDP:
    return parseUDP(packet, len, offset, pkt);
  default:
    return -2;
  }
}

static inline uint32_t parseIPv4(const uint8_t *packet, uint32_t len, uint32_t offset, struct Packet *pkt) {
  uint8_t header_length = packet[offset] & 0b00001111;

  pkt->addrs.ipv4.src_ip = *(uint32_t *)(packet + offset + IPv4_SRC_ADDRESS_OFFSET);
  pkt->addrs.ipv4.dst_ip = *(uint32_t *)(packet + offset + IPv4_DST_ADDRESS_OFFSET);

  pkt->proto = packet[offset + IPv4_PROTOCOL_OFFSET];
  
  return header_length * 4;
}

static inline int parseIPv6(const uint8_t *packet, uint32_t len, uint32_t offset, struct Packet *pkt) {
  pkt->proto = packet[offset + IPv6_NEXT_HEADER_OFFSET];
  memcpy(&pkt->addrs.ipv6.src_ip, packet + offset + IPv6_SRC_ADDRESS_OFFSET, sizeof(pkt->addrs.ipv6.src_ip));
  memcpy(&pkt->addrs.ipv6.dst_ip, packet + offset + IPv6_DST_ADDRESS_OFFSET, sizeof(pkt->addrs.ipv6.dst_ip));

  return IPv6_HEADER_SIZE;
}

// Assumption: [len] > [ETHERNET_ETHERTYPE_OFFSET]
static uint32_t findVlanOffset(const uint8_t *packet, uint32_t len) {
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

static inline int handleIPv4(const XDPPacketWrapper *data, uint32_t vlan_offset, struct Packet *packet) {
  uint32_t ip_offset = parseIPv4(data->packet, data->length - vlan_offset - ETHERNET_HEADER_SIZE, vlan_offset + ETHERNET_HEADER_SIZE, packet);

  assert(data->length > (vlan_offset + ETHERNET_HEADER_SIZE + ip_offset));
  int err = parseL3Proto(data->packet, data->length, vlan_offset + ETHERNET_HEADER_SIZE + ip_offset, packet);

  char src_buffer[INET_ADDRSTRLEN + 1];
  char dst_buffer[INET_ADDRSTRLEN + 1];
  
  inet_ntop(AF_INET, &packet->addrs.ipv4.src_ip, src_buffer, sizeof(src_buffer) - 1);
  inet_ntop(AF_INET, &packet->addrs.ipv4.dst_ip, dst_buffer, sizeof(dst_buffer) - 1);

  if (err == 0) {
    LOG_PRINT("Protocol: 0x%02x/0x%04x (%s/IPv4): %s:%u -> %s:%u\n", packet->proto, packet->type, getL3ProtocolName(packet->proto), src_buffer, packet->src_port, dst_buffer, packet->dst_port);
  } else {
    LOG_PRINT("Protocol: 0x%02x/0x%04x (%s/IPv4): %s -> %s\n", packet->proto, packet->type, getL3ProtocolName(packet->proto), src_buffer, dst_buffer);
  }

  return err;
}


static inline int handleIPv6(const XDPPacketWrapper *data, uint32_t vlan_offset, struct Packet *packet) {
  uint32_t offset = parseIPv6(data->packet, data->length - vlan_offset - ETHERNET_HEADER_SIZE, vlan_offset + ETHERNET_HEADER_SIZE, packet);
  int err = parseL3Proto(data->packet, data->length, offset, packet);

  char src_buffer[INET6_ADDRSTRLEN + 1];
  char dst_buffer[INET6_ADDRSTRLEN + 1];
  
  inet_ntop(AF_INET6, &packet->addrs.ipv6.src_ip, src_buffer, sizeof(src_buffer) - 1);
  inet_ntop(AF_INET6, &packet->addrs.ipv6.dst_ip, dst_buffer, sizeof(dst_buffer) - 1);

  if (err == 0) {
    LOG_PRINT("Protocol: 0x%02x/0x%04x (%s/IPv6): %s:%u -> %s:%u\n", packet->proto, packet->type, getL3ProtocolName(packet->proto), src_buffer, packet->src_port, dst_buffer, packet->dst_port);
  } else {
    LOG_PRINT("Protocol: 0x%02x/0x%04x (%s/IPv6): %s -> %s\n", packet->proto, packet->type, getL3ProtocolName(packet->proto), src_buffer, dst_buffer);
  }

  return err;
}

void *parse_protocols(void *args) {
  int err = 0;
  const XDPPacketWrapper *data = args;
  struct Packet *packet = packet_alloc();

  uint32_t vlan_offset = findVlanOffset(data->packet, data->length);
  packet->type = ntohs(*(uint16_t *)(data->packet + vlan_offset + ETHERNET_ETHERTYPE_OFFSET));


  if (vlan_offset + ETHERNET_HEADER_SIZE > data->length) {
    LOG_PRINT("vlan_offset(%u) + ETHERNET_HEADER_SIZE(%u) > data->length(%u)\n", vlan_offset, ETHERNET_HEADER_SIZE, data->length);
    packet_dealloc(packet);
    return nullptr;
  }
  
  switch (packet->type) {
    case PROTOCOL_IPV4:
      handleIPv4(data, vlan_offset, packet);
      break;
    case PROTOCOL_IPV6:
      handleIPv6(data, vlan_offset, packet);
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
