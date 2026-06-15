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

#include <linux/if_link.h>

#include "protocols.h"

#define CHUNK_SIZE 4096
#define CHUNK_COUNT 4096

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

#define SET_RING_CONSUMER(name) atomic_uint_least32_t * name##_ring_consumer = (atomic_uint_least32_t *)( (char *) name##_ring_mmap + offsets. name .consumer )
#define SET_RING_PRODUCER(name) atomic_uint_least32_t * name##_ring_producer = (atomic_uint_least32_t *)( (char *) name##_ring_mmap + offsets. name .producer )

static const __u32 RING_SIZE = 4096;

//struct xsk_socket *xsk;
//struct xsk_umem *umem;
static void *umem_area = NULL;
static int sockfd = 0;

static inline void setxdgsockopt(int sockfd, const __u32 *ring_size, const int optname, const char * restrict optname_s){
  if(setsockopt(sockfd, SOL_XDP, optname, ring_size, sizeof(*ring_size)) < 0) {
    fprintf(stderr, "Failed to set XSK %s buffer: %s\n", optname_s, strerror(errno));
    munmap(umem_area, UMEM_SIZE);
    exit(EXIT_FAILURE);
  }
}

void handle_packet(const uint8_t *packet) {
  uint16_t l2proto = *(uint16_t *)(packet + ETHERNET_PROTOCOL_OFFSET);
  printf("Protocol: 0x%02X", l2proto);
}

void handle_sigint(int sig) {
  fprintf(stderr, "Caught sigint, cleaning up...\n");
  munmap(umem_area, UMEM_SIZE);
  close(sockfd);
  exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[argc]) {

  if (argc < 2) {
    fprintf(stderr, "Usage: %s [INTERFACE]", argv[0]);
  }

  unsigned int netif_id = if_nametoindex(argv[1]);

  int err = 0;
  //unsigned char umem[UMEM_SIZE];
  umem_area = mmap(NULL, UMEM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  if (umem_area == MAP_FAILED) {
    fprintf(stderr, "Failed to mmap: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  struct xdp_umem_reg umem_reg = {
    .addr = (uint64_t)umem_area,
    .len = UMEM_SIZE,
    .chunk_size = CHUNK_SIZE,
    .headroom = 0,
    .flags = 0
  };

  sockfd = socket(AF_XDP, SOCK_RAW, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Failed to open a socket: %s\n", strerror(errno));
    munmap(umem_area, UMEM_SIZE);
    return EXIT_FAILURE;
  }

  signal(SIGINT, handle_sigint);

  if(setsockopt(sockfd, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg)) < 0) {
    fprintf(stderr, "Failed to set XDP_UMEM_REG buffer: %s\n", strerror(errno));
    munmap(umem_area, UMEM_SIZE);
    exit(EXIT_FAILURE);
  }

  setxdgsockopt(sockfd, &RING_SIZE, XDP_TX_RING, "XDP_TX_RING");
  setxdgsockopt(sockfd, &RING_SIZE, XDP_RX_RING, "XDP_RX_RING");
  setxdgsockopt(sockfd, &RING_SIZE, XDP_UMEM_FILL_RING, "XDP_UMEM_FILL_RING");
  setxdgsockopt(sockfd, &RING_SIZE, XDP_UMEM_COMPLETION_RING, "XDP_UMEM_COMPLETION_RING");

  struct xdp_mmap_offsets offsets;
  unsigned int len = sizeof(offsets);
  if (getsockopt(sockfd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &len) < 0) {
    fprintf(stderr, "Failed to get sockopt: %s", strerror(errno));
    munmap(umem_area, UMEM_SIZE);
    return EXIT_FAILURE;
  }

  //void *rx_ring_mmap = mmap(NULL, size_t len, int prot, int flags, int fd, __off_t offset);
  SET_MMAP_RING(rx, RING_SIZE_DESC);
  if (rx_ring_mmap == MAP_FAILED) {
    fprintf(stderr, "Failed to allocate rx_ring_mmap: %s\n", strerror(errno));
    err = EXIT_FAILURE;
    goto initial_fail;
  }
  SET_MMAP_RING(tx, RING_SIZE_DESC);
  if (tx_ring_mmap == MAP_FAILED) {
    fprintf(stderr, "Failed to allocate tx_ring_mmap: %s\n", strerror(errno));
    err = EXIT_FAILURE;
    goto tx_fail;
  }
  SET_MMAP_RING(fr, RING_SIZE_UMEM);
  if (fr_ring_mmap == MAP_FAILED) {
    fprintf(stderr, "Failed to allocate fr_ring_mmap: %s\n", strerror(errno));
    err = EXIT_FAILURE;
    goto fr_fail;
  }
  SET_MMAP_RING(cr, RING_SIZE_UMEM);
  if (cr_ring_mmap == MAP_FAILED) {
    fprintf(stderr, "Failed to allocate cr_ring_mmap: %s\n", strerror(errno));
    err = EXIT_FAILURE;
    goto cr_fail;
  }

  SET_RING_CONSUMER(rx);
  SET_RING_CONSUMER(tx);
  SET_RING_CONSUMER(fr);
  SET_RING_CONSUMER(cr);


  SET_RING_PRODUCER(rx);
  SET_RING_PRODUCER(tx);
  SET_RING_PRODUCER(fr);
  SET_RING_PRODUCER(cr);
  
  struct xdp_desc *rx_ring = (struct xdp_desc *)((char *)rx_ring_mmap + offsets.rx.desc);
  struct xdp_desc *tx_ring = (struct xdp_desc *)((char *)tx_ring_mmap + offsets.tx.desc);
  uint64_t *fr_ring = (uint64_t *)((char *)fr_ring_mmap + offsets.fr.desc);
  uint64_t *cr_ring = (uint64_t *)((char *)cr_ring_mmap + offsets.cr.desc);

  
  struct sockaddr_xdp sockaddr = {
    .sxdp_family = AF_XDP,
    .sxdp_flags = XDP_COPY /* XDP_ZEROCOPY */,
    .sxdp_ifindex = netif_id,
    .sxdp_queue_id = 0,
    .sxdp_shared_umem_fd = 0,
  };

  if (bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr_xdp)) < 0) {
    fprintf(stderr, "Failed to bind the socket");
    err = EXIT_FAILURE;
    goto cleanup;
  }

  struct xdp_program *prog = nullptr;
  struct bpf_object *bpf_obj = bpf_object__open_file("build/pf.bpf.o", nullptr);
  if (libbpf_get_error(bpf_obj)) {
    fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
    goto cleanup;
  }

  if (bpf_object__load(bpf_obj) < 0) {
    fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
    goto cleanup;
  }

  struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
  if (map == nullptr) {
    fprintf(stderr, "Failed to find xsks_map\n");
    goto cleanup;
  }

  int map_fd = bpf_map__fd(map);
  uint32_t key = 0;

  int value = sockfd;
  if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0) {
    fprintf(stderr, "Failed to update xsks_map");
    goto cleanup;
  }

  prog = xdp_program__from_bpf_obj(bpf_obj, "xdp_prog.o");

  if (prog == nullptr) {
    fprintf(stderr, "Failed to create xdp_program\n");
    goto cleanup;
  }

  if (xdp_program__attach(prog, netif_id, XDP_MODE_NATIVE, 0) < 0) {
    fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
    goto cleanup;
  } 




  uint32_t fill_count = RING_SIZE;
  for (int i = 0; i < fill_count; i++) {
      __u64 addr = i * CHUNK_SIZE;
      fr_ring[*fr_ring_producer] = addr;
      *fr_ring_producer = (*fr_ring_producer + 1) & (RING_SIZE - 1);
  }

  uint32_t rx_cons = *rx_ring_consumer; 
  uint32_t tx_prod = *tx_ring_producer;
  uint32_t cr_cons = *cr_ring_consumer;
  uint32_t fr_prod = *fr_ring_producer;

  while (true) {
    struct pollfd pfd = { .fd = sockfd, .events = POLLIN | POLLOUT };
    int ret = poll(&pfd, 1, -1);   // wait forever
    if (ret < 0) {
        perror("poll");
        break;
    }

    for (; ;) {
      uint32_t rx_prod = atomic_load_explicit(rx_ring_producer, memory_order_acquire);
      while (rx_cons != rx_prod) {
        printf("Got a packet!");
        struct xdp_desc desc = rx_ring[rx_cons];
        void *packet = (char *)umem_area + desc.addr;
        handle_packet(packet);

        uint32_t tx_cons = atomic_load_explicit(tx_ring_consumer, memory_order_acquire);
        if (((tx_prod - tx_cons) & (RING_SIZE - 1)) == (RING_SIZE - 1)) {
            // TX ring is full, wait and retry
            break;
        }

        // reuse the same addr and len
        tx_ring[tx_prod] = desc;              
        tx_prod = (tx_prod + 1) & (RING_SIZE - 1);
        atomic_store_explicit(tx_ring_producer, tx_prod, memory_order_release);

        rx_cons = (rx_cons + 1) & (RING_SIZE - 1);
      }

      atomic_store_explicit(rx_ring_consumer, rx_cons, memory_order_release);
      sendto(sockfd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    }

    for (uint32_t cr_prod = atomic_load_explicit(cr_ring_producer, memory_order_acquire); cr_cons != cr_prod;) {
        if (cr_cons == cr_prod) {
            break;
        }
        uint64_t addr = cr_ring[cr_cons];
        cr_cons = (cr_cons + 1) & (RING_SIZE - 1);

        // return to fill ring
        fr_ring[*fr_ring_producer] = addr;
        fr_prod = (fr_prod + 1) & (RING_SIZE - 1);
        // write fill producer (with release)
    }

    atomic_store_explicit(cr_ring_consumer, cr_cons, memory_order_release);
    atomic_store_explicit(fr_ring_producer, fr_prod, memory_order_release);
  }

    // (Optional) sleep / poll if no work was done



cleanup:
  UNMAP_MMAP_RING(cr, RING_SIZE_UMEM);
cr_fail:
  UNMAP_MMAP_RING(fr, RING_SIZE_UMEM);
fr_fail:
  UNMAP_MMAP_RING(tx, RING_SIZE_DESC);
tx_fail:
  UNMAP_MMAP_RING(rx, RING_SIZE_DESC);
initial_fail:
  munmap(umem_area, UMEM_SIZE);
  
  close(sockfd);
  //buffer = aligned_alloc(getpagesize(), UMEM_SIZE);
  //xsk_umem__create(&umem_area, buffer, UMEM_SIZE, struct xsk_ring_prod *fill, struct xsk_ring_cons *comp, const struct xsk_umem_config *config);

  return err;
}
