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


struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_pf(struct xdp_md *ctx) {
  __u32 queue_id = ctx->rx_queue_index;
  if (bpf_map_lookup_elem(&xsks_map, &queue_id)) {
    bpf_printk("Redirected to userspace");
    return bpf_redirect_map(&xsks_map, queue_id, 0);
  }

  bpf_printk("Redirected to kernel NS");
  return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPL";

