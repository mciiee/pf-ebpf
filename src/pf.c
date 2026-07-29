#ifndef asm 
#define asm __asm__
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

//#include "protocols.h"

//#define DEBUG

#ifdef DEBUG 
#define IF_DEBUG(stmt) stmt
#else
#define IF_DEBUG(stmt)
#endif

//struct {
//	__uint(priority, 10);
//	__uint(XDP_PASS, 1);
//	__uint(XDP_DROP, 1);
//} XDP_RUN_CONFIG(my_xdp_func);


//struct {
//  __uint(type, BPF_MAP_TYPE_HASH);
//  __type(key, __u32);
//  __type(value, int);
//  __uint(max_entries, 1);
//  __uint(pinning, LIBBPF_PIN_BY_NAME);
//} pf_fd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");


SEC("xdp")
int xdp_pf(struct xdp_md *ctx) {
  __u32 queue_id = ctx->rx_queue_index;
  IF_DEBUG(bpf_printk("queue_id: %d", queue_id));
  if (bpf_map_lookup_elem(&xsks_map, &queue_id)) {
    IF_DEBUG(bpf_printk("Redirected to userspace"));
    return bpf_redirect_map(&xsks_map, queue_id, 0);
  }
  IF_DEBUG(bpf_printk("Redirected to kernel NS"));
  return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPL";

