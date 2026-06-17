#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_xdp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <sys/mman.h>
#include <net/if.h>
#include <poll.h>
#include <sys/resource.h>

#include <linux/if_link.h>

#include "protocols.h"
#include "xsk_umem_info.h"


#define DEFAULT_ERROR_MESSAGE_BUFFER_SIZE 1024

#define EXPECTED_HW_RING_SIZE 512

#define BPF_OBJECT_PATH "build/pf.bpf.o"

#define XSKS_MAP_PIN_PATH "/sys/fs/bpf/xdp/globals/xsks_map"

#define CHUNK_SIZE 4096
#define CHUNK_COUNT 4096

#ifndef max
#define max(a,b) a < b? a: b
#endif

#define UMEM_SIZE (CHUNK_SIZE * CHUNK_COUNT)

#define RING_SIZE_DESC   (sizeof(struct xdp_desc))  // RX / TX
#define RING_SIZE_UMEM   (sizeof(__u64))            // FILL / COMPLETION
//#define RING_SIZE_UMEM   (sizeof(struct xdp_desc))            // FILL / COMPLETION

#define rx_RING XDP_PGOFF_RX_RING
#define tx_RING XDP_PGOFF_TX_RING
#define fr_RING XDP_UMEM_PGOFF_FILL_RING
#define cr_RING XDP_UMEM_PGOFF_COMPLETION_RING

#define SET_MMAP_RING(name, size) void * name##_ring_mmap = mmap(NULL, offsets. name .desc + RING_SIZE * size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, sockfd, name##_RING) 
#define UNMAP_MMAP_RING(name, size) munmap( name##_ring_mmap ,  offsets. name .desc + RING_SIZE * size)

#define SET_RING_CONSUMER(name) __u32 * name##_ring_consumer = (__u32 *)( (char *) name##_ring_mmap + offsets. name .consumer )
#define SET_RING_PRODUCER(name) __u32 * name##_ring_producer = (__u32 *)( (char *) name##_ring_mmap + offsets. name .producer )

static const __u32 RING_SIZE = 4096;

//struct xsk_socket *xsk;
static void *umem_area = NULL;
static int sockfd = 0;

static inline int remove_memlimit(void) {
  struct rlimit r = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    fprintf(stderr, "Error: Failed to unlock memory limit \"%s\"\n", strerror(errno));
		return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

static inline void setxdgsockopt(int sockfd, const __u32 *ring_size, const int optname, const char * restrict optname_s){
  if(setsockopt(sockfd, SOL_XDP, optname, ring_size, sizeof(*ring_size)) < 0) {
    fprintf(stderr, "Failed to set XSK %s buffer: %s\n", optname_s, strerror(errno));
    munmap(umem_area, UMEM_SIZE);
    exit(EXIT_FAILURE);
  }
}

static void handle_packet(const uint8_t *packet) {
  uint16_t l2proto = *(uint16_t *)(packet + ETHERNET_PROTOCOL_OFFSET);
  printf("Protocol: 0x%02X", l2proto);
}

static void handle_sigint(int sig) {
  fprintf(stderr, "Caught sigint, cleaning up...\n");
  munmap(umem_area, UMEM_SIZE);
  close(sockfd);
  exit(EXIT_SUCCESS);
}

int load_bpf_prog(int netif_id, struct xdp_program **bpf_prog) {
  char errbuff[1024];
  int err = 0;

  auto prog = xdp_program__open_file("build/pf.bpf.o", "xdp", nullptr);
  err = libxdp_get_error(prog);
  if (err) {
    libxdp_strerror(err, errbuff, sizeof(errbuff)/sizeof(errbuff[0]) - 1);
    fprintf(stderr, "ERROR: program loading failed: %s\n", errbuff);
    EXIT_FAILURE;
  }
  printf("Loaded XDP program: %p\n", prog);

  err = xdp_program__attach(prog, netif_id, XDP_MODE_UNSPEC, 0);
  if (err) {
    libxdp_strerror(err, errbuff, sizeof(errbuff)/sizeof(errbuff[0]) - 1);
    fprintf(stderr, "ERROR: program attaching failed: %s\n", errbuff);
    return EXIT_FAILURE;
  }
  printf("Attached XDP program: %p\n", prog);

  *bpf_prog = prog;

  return EXIT_SUCCESS;
}


int cleanup_xdp_progs(int netif_id, struct xdp_program *prog){
  char buffer[DEFAULT_ERROR_MESSAGE_BUFFER_SIZE];
  int err = 0;
  bool fail = false;
  
  err = xdp_program__detach(prog, netif_id, XDP_MODE_UNSPEC, 0);
  if (err < 0) {
    libxdp_strerror(err, buffer, DEFAULT_ERROR_MESSAGE_BUFFER_SIZE - 1);
    fprintf(stderr, "Failed to detach an XDP program: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }
  printf("Detached XDP program\n");

  xdp_program__close(prog);
  return EXIT_SUCCESS;
}

static struct xsk_umem_info *xsk_configure_umem(void *buffer, uint64_t size) {
  int err = 0;
  struct xsk_umem_config cfg = {
    .fill_size = max(XSK_RING_PROD__DEFAULT_NUM_DESCS, RING_SIZE) * 2,
    .comp_size = max(XSK_RING_PROD__DEFAULT_NUM_DESCS, RING_SIZE),
    .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
    .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    .flags = 0
  };

  struct xsk_umem_info *umem = calloc(1, sizeof(*umem));

  if (!umem) {
    fprintf(stderr, "Failed to allocate xsk_umem_info: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }
  err = xsk_umem__create(&umem->umem, umem_area, size, &umem->fq, &umem->cq, &cfg);
  if (err) {
    return nullptr;
  }

  umem->buffer = umem_area;
  return umem;
}

int main(int argc, char *argv[argc]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [INTERFACE]", argv[0]);
    return EXIT_FAILURE;
  }

  int err = 0;

  err = remove_memlimit();
  if (err != EXIT_SUCCESS) {
    return EXIT_FAILURE;
  }
  

  unsigned int netif_id = if_nametoindex(argv[1]);
  if (netif_id == 0) {
    fprintf(stderr, "Failed to lookup network interface id: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }
  printf("Looked up netif_id: %u\n", netif_id);

  
  struct xdp_program *prog = nullptr;
  err = load_bpf_prog(netif_id, &prog);

  if (err != EXIT_SUCCESS) {
    fprintf(stderr, "Failed to load BPF program\n");
    return EXIT_FAILURE;
  }

  umem_area = mmap(nullptr, CHUNK_SIZE * CHUNK_COUNT, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (umem_area == MAP_FAILED) {
    fprintf(stderr, "Failed to allocate umem_area\n");
    goto cleanup;
  }

  struct xsk_umem_info *umem = xsk_configure_umem(umem_area, CHUNK_SIZE * CHUNK_COUNT);


  struct xsk_umem_opts opts = {};

  //xsk_umem__create_opts(void *umem_area, struct xsk_ring_prod *fill, struct xsk_ring_cons *comp, struct xsk_umem_opts *opts)

cleanup:

  err = cleanup_xdp_progs(netif_id, prog);
  if (err != EXIT_SUCCESS) {
    fprintf(stderr, "Failed to unload BPF program\n");
    return EXIT_FAILURE;
  }


  return EXIT_SUCCESS;
}

