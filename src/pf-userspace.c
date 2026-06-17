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

#include "log.h"
#include "protocols.h"
#include "xsk_umem_info.h"
#include "ErrorJump.h"


#define DEFAULT_ERROR_MESSAGE_BUFFER_SIZE 1024

#define EXPECTED_HW_RING_SIZE 512

#define BPF_OBJECT_PATH "build/pf.bpf.o"

#define XSKS_MAP_PIN_PATH "/sys/fs/bpf/xdp/globals/xsks_map"

//#define CHUNK_SIZE 4096
//#define CHUNK_COUNT 4096

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define UMEM_SIZE (NUM_FRAMES * FRAME_SIZE)

#ifndef max
#define max(a,b) a < b? a: b
#endif

//#define UMEM_SIZE (CHUNK_SIZE * CHUNK_COUNT)

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

//static const __u32 RING_SIZE = 4096;
constexpr __u32 RING_SIZE = 2048;

//struct xsk_socket *xsk;
static void *umem_area = NULL;
static int sockfd = 0;

static inline int remove_memlimit(void) {
  struct rlimit r = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    LOG_ERROR("Error: Failed to unlock memory limit \"%s\"\n", strerror(errno));
		return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

static inline void setxdgsockopt(int sockfd, const __u32 *ring_size, const int optname, const char * restrict optname_s){
  if(setsockopt(sockfd, SOL_XDP, optname, ring_size, sizeof(*ring_size)) < 0) {
    LOG_ERROR("Failed to set XSK %s buffer: %s\n", optname_s, strerror(errno));
    munmap(umem_area, UMEM_SIZE);
    exit(EXIT_FAILURE);
  }
}

static void handle_packet(const uint8_t *packet) {
  uint16_t l2proto = *(uint16_t *)(packet + ETHERNET_PROTOCOL_OFFSET);
  LOG_PRINT("Protocol: 0x%02X", l2proto);
}

static void handle_sigint(int sig) {
  LOG_ERROR("Caught sigint, cleaning up...\n");
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
    LOG_ERROR("ERROR: program loading failed: %s\n", errbuff);
    EXIT_FAILURE;
  }
  LOG_PRINT("Loaded XDP program: %p\n", prog);

  err = xdp_program__attach(prog, netif_id, XDP_MODE_UNSPEC, 0);
  if (err) {
    libxdp_strerror(err, errbuff, sizeof(errbuff)/sizeof(errbuff[0]) - 1);
    LOG_ERROR("ERROR: program attaching failed: %s\n", errbuff);
    return EXIT_FAILURE;
  }
  LOG_PRINT("Attached XDP program: %p\n", prog);

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
    LOG_ERROR("Failed to detach an XDP program: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }
  LOG_PRINT("Detached XDP program\n");

  xdp_program__close(prog);
  return EXIT_SUCCESS;
}


enum ErrorJump xsk_configure_umem(struct xsk_umem **umem, struct xsk_ring_prod *fill_ring, struct xsk_ring_cons *comp_ring) {
  char errbuf[DEFAULT_ERROR_MESSAGE_BUFFER_SIZE];
  int err = 0;

  umem_area = mmap(nullptr, UMEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (umem_area == MAP_FAILED) {
    LOG_ERROR("Failed to allocate umem_area\n");
    return ERROR_JUMP_UMEM_CLEANUP;
  }

  struct xsk_umem_config umem_cfg = {
    .fill_size = RING_SIZE,
    .comp_size = RING_SIZE,
    .frame_size = FRAME_SIZE,
    .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    .flags = 0
  };

  err = xsk_umem__create(umem, umem_area, UMEM_SIZE, fill_ring, comp_ring, &umem_cfg);
  if (err) {
    LOG_ERROR("Failed to create UMEM: %s\n", strerror(-err));
    return ERROR_JUMP_XDP_PROG_CLEANUP;
  }

  LOG_PRINT("Configured UMEM\n");

  return ERROR_JUMP_NO_ERROR;
}

enum ErrorJump xsk_configure_socket(const char *iface, struct xsk_umem *umem, struct xsk_socket **xsk, struct xsk_ring_prod *tx_ring, struct xsk_ring_cons *rx_ring) {
  int err = 0;
  struct xsk_socket_config cfg = {
        .rx_size = RING_SIZE,
        .tx_size = RING_SIZE,
        .libbpf_flags = 0,
        // IMPORTANT: Change if necessary
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = 0,
  };

  err = xsk_socket__create(xsk, iface, 0, umem, rx_ring, tx_ring, &cfg);

  if (err) {
    LOG_ERROR("Failed to create AF_XDP socket: %s\n", strerror(-err));
    return ERROR_JUMP_UMEM_CLEANUP;
  }

  return 0;
}

#define ERROR_JUMP(errjump) \
  switch (errjump) { \
    case ERROR_JUMP_UMEM_CLEANUP: \
      goto umem_cleanup; \
    case ERROR_JUMP_XDP_PROG_CLEANUP: \
      goto xdp_prog_cleanup; \
    default: \
      break; \
  } \

int main(int argc, char *argv[argc]) {
  if (argc < 2) {
    LOG_ERROR("Usage: %s [INTERFACE]", argv[0]);
    return EXIT_FAILURE;
  }

  const char *iface = argv[1];

  int err = 0;

  err = remove_memlimit();
  if (err != EXIT_SUCCESS) {
    return EXIT_FAILURE;
  }
  

  unsigned int netif_id = if_nametoindex(iface);
  if (netif_id == 0) {
    LOG_ERROR("Failed to lookup network interface id: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }
  LOG_PRINT("Looked up netif_id: %u\n", netif_id);

  
  struct xdp_program *prog = nullptr;
  err = load_bpf_prog(netif_id, &prog);

  if (err != EXIT_SUCCESS) {
    LOG_ERROR("Failed to load BPF program\n");
    return EXIT_FAILURE;
  }

  umem_area = mmap(nullptr, UMEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (umem_area == MAP_FAILED) {
    LOG_ERROR("Failed to allocate umem_area\n");
    goto umem_cleanup;
  }
  LOG_PRINT("Allocated umem_area\n");

  struct xsk_umem *umem = nullptr;
  struct xsk_ring_prod fill_ring;
  struct xsk_ring_cons comp_ring;


  enum ErrorJump errjump = xsk_configure_umem(&umem, &fill_ring, &comp_ring);

  ERROR_JUMP(errjump);

  struct xsk_ring_prod tx_ring;
  struct xsk_ring_cons rx_ring;
  struct xsk_socket *xsk = nullptr;

  errjump = xsk_configure_socket(iface, umem, &xsk, &tx_ring, &rx_ring);

  ERROR_JUMP(errjump);


umem_cleanup:
  
    munmap(umem_area, UMEM_SIZE);
    LOG_PRINT("Deallocated umem_area\n");

xdp_prog_cleanup:

  err = cleanup_xdp_progs(netif_id, prog);
  if (err != EXIT_SUCCESS) {
    LOG_ERROR("Failed to unload BPF program\n");
    return EXIT_FAILURE;
  }


  return EXIT_SUCCESS;
}

