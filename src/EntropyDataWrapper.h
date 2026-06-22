#ifndef XDP_PACKET_WRAPPER_H
#define XDP_PACKET_WRAPPER_H
#include <stdint.h>
typedef struct XDPPacketWrapper {
  const uint8_t *packet;
  uint32_t length;
} XDPPacketWrapper;
#endif
