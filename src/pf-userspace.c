#include <errno.h>
#include <linux/if_xdp.h>
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

 
#define CHUNK_SIZE 4096
#define CHUNK_COUNT 4096

#define UMEM_SIZE (CHUNK_SIZE * CHUNK_COUNT)

#define rx_RING XDP_PGOFF_RX_RING
#define tx_RING XDP_PGOFF_TX_RING
#define tx_RING XDP_PGOFF_TX_RING
#define fr_RING XDP_UMEM_PGOFF_FILL_RING
#define cr_RING XDP_UMEM_PGOFF_COMPLETION_RING

#define SET_MMAP_RING(name) void * name##_ring_mmap = mmap(NULL, offsets. name .desc + RING_SIZE * sizeof(struct xdp_desc), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, sockfd, name##_RING) 
#define UNMAP_MMAP_RING(name) munmap( name##_ring_mmap ,  offsets. name .desc + RING_SIZE * sizeof(struct xdp_desc))

#define SET_RING_CONSUMER(name) __u32 * name##_ring_consumer = name##_ring_mmap + offsets. name .consumer
#define SET_RING_PRODUCER(name) __u32 * name##_ring_producer = name##_ring_mmap + offsets. name .producer

static const int RING_SIZE = 2048;

struct xsk_socket *xsk;
//struct xsk_umem *umem;
static void *umem_area = NULL;

static inline void setxdgsockopt(int sockfd, const int ring_size, const int optname, const struct xdp_umem_reg * restrict umem_reg, const char * restrict optname_s){
  if(setsockopt(sockfd, SOL_XDP, optname, umem_reg, sizeof(*umem_reg)) < 0) {
    fprintf(stderr, "Failed to set XSK %s buffer: %s\n", optname_s, strerror(errno));
    munmap(umem_area, UMEM_SIZE);
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char *argv[argc]) {
  int err = 0;
  //unsigned char umem[UMEM_SIZE];
  umem_area = mmap(NULL, UMEM_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);

  struct xdp_umem_reg umem_reg = {
    .addr = (uint64_t)umem_area,
    .len = UMEM_SIZE,
    .chunk_size = CHUNK_SIZE,
    .headroom = 0,
    .flags = 0
  };

  int sockfd = socket(AF_XDP, SOCK_RAW, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Failed to open a socket: %s\n", strerror(errno));
    munmap(umem_area, UMEM_SIZE);
    return EXIT_FAILURE;
  }

  setxdgsockopt(sockfd, RING_SIZE, XDP_UMEM_REG, &umem_reg, "XDP_UMEM_REG");
  setxdgsockopt(sockfd, RING_SIZE, XDP_TX_RING, &umem_reg, "XDP_TX_RING");
  setxdgsockopt(sockfd, RING_SIZE, XDP_RX_RING, &umem_reg, "XDP_RX_RING");
  setxdgsockopt(sockfd, RING_SIZE, XDP_UMEM_FILL_RING, &umem_reg, "XDP_UMEM_FILL_RING");
  setxdgsockopt(sockfd, RING_SIZE, XDP_UMEM_COMPLETION_RING, &umem_reg, "XDP_UMEM_COMPLETION_RING");

  struct xdp_mmap_offsets offsets;
  unsigned int len = sizeof(offsets);
  if (getsockopt(sockfd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &len) < 0) {
    fprintf(stderr, "Failed to get sockopt: %s", strerror(errno));
    munmap(umem_area, UMEM_SIZE);
    return EXIT_FAILURE;
  }

  //void *rx_ring_mmap = mmap(NULL, size_t len, int prot, int flags, int fd, __off_t offset);
  SET_MMAP_RING(rx);
  if (rx_ring_mmap == (void *)-1) {
    fprintf(stderr, "Failed to allocate rx_ring_mmap: %s\n", strerror(errno));
    err = EXIT_FAILURE;
    goto initial_fail;
  }
  SET_MMAP_RING(tx);
  if (tx_ring_mmap == (void *)-1) {
    fprintf(stderr, "Failed to allocate tx_ring_mmap: %s\n", strerror(errno));
    err = EXIT_FAILURE;
    goto tx_fail;
  }
  SET_MMAP_RING(fr);
  if (fr_ring_mmap == (void *)-1) {
    fprintf(stderr, "Failed to allocate fr_ring_mmap: %s\n", strerror(errno));
    err = EXIT_FAILURE;
    goto fr_fail;
  }
  SET_MMAP_RING(cr);
  if (fr_ring_mmap == (void *)-1) {
    fprintf(stderr, "Failed to allocate fr_ring_mmap: %s\n", strerror(errno));
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
  
  struct xdp_desc *rx_ring = rx_ring_mmap + offsets.rx.desc;
  struct xdp_desc *tx_ring = tx_ring_mmap + offsets.tx.desc;
  struct xdp_desc *fr_ring = fr_ring_mmap + offsets.fr.desc;
  struct xdp_desc *cr_ring = cr_ring_mmap + offsets.cr.desc;

  
  struct sockaddr_xdp sockaddr = {
    .sxdp_family = AF_XDP,
    .sxdp_flags = XDP_ZEROCOPY,
    .sxdp_ifindex = 0,
    .sxdp_queue_id = 0,
    .sxdp_shared_umem_fd = sockfd,
  };

  if (bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr_xdp)) < 0) {
    fprintf(stderr, "Failed to bind the socket");
    goto fail;
    err = EXIT_FAILURE;
  }


fail:
  UNMAP_MMAP_RING(cr);
cr_fail:
  UNMAP_MMAP_RING(fr);
fr_fail:
  UNMAP_MMAP_RING(tx);
tx_fail:
  UNMAP_MMAP_RING(rx);
initial_fail:
  munmap(umem_area, UMEM_SIZE);
  
  //buffer = aligned_alloc(getpagesize(), UMEM_SIZE);
  //xsk_umem__create(&umem_area, buffer, UMEM_SIZE, struct xsk_ring_prod *fill, struct xsk_ring_cons *comp, const struct xsk_umem_config *config);

  return err;
}
