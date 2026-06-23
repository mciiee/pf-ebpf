#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_xdp.h>
#include <math.h>
#include <netinet/in.h>
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
#include <arpa/inet.h>
#include <pthread.h>

#include <linux/if_link.h>

#include "log.h"
#include "protocols.h"
#include "ErrorJump.h"
#include "EntropyDataWrapper.h"
#include "mempool.h"



#define THREAD_COUNT 2

#define DEFAULT_ERROR_MESSAGE_BUFFER_SIZE 1024

#define EXPECTED_HW_RING_SIZE 512

#define BPF_OBJECT_PATH "build/pf.bpf.o"

#define XSKS_MAP_PIN_PATH "/sys/fs/bpf/xsks_map"

//#define CHUNK_SIZE 4096
//#define CHUNK_COUNT 4096

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define UMEM_SIZE (NUM_FRAMES * FRAME_SIZE)

#ifndef PACKET_BUFFER_SIZE
#define PACKET_BUFFER_SIZE 1024 * 1024
#endif

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



#define ERROR_JUMP(errjump) \
  switch (errjump) { \
    case ERROR_JUMP_UMEM_CLEANUP: \
      goto umem_cleanup; \
    case ERROR_JUMP_XDP_PROG_CLEANUP: \
      goto xdp_prog_cleanup; \
    case ERROR_JUMP_SOCKET_CLEANUP: \
      goto socket_cleanup; \
    case ERROR_JUMP_ADDRS_CLEANUP: \
      goto cleanup; \
    case ERROR_JUMP_MEMPOOL_CLEANUP: \
      goto mempool_cleanup; \
    case ERROR_JUMP_NO_ERROR: \
      break; \
  } \

constexpr size_t UINT8_SIZE = 256;
//static const __u32 RING_SIZE = 4096;
constexpr __u32 RING_SIZE = 4096;
constexpr size_t ENTROPY_THREAD_ID = 1;

//struct xsk_socket *xsk;
static void *umem_area = NULL;
static int sockfd = 0;
static atomic_bool run = true;
static pthread_t threads[THREAD_COUNT];



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



static void *calculate_entropy(void *arg) {
  //LOG_PRINT("Entropy enter\n");
  const XDPPacketWrapper *data = arg;
  const uint8_t *packet = data->packet;
  const uint32_t len = data->length;

  double *ret = malloc(sizeof(double));

  uint32_t charmap[UINT8_SIZE] = {0};
  double res = 0;
  for (uint32_t i = 0; i < len; i++) {
    charmap[packet[i]]++;
  }
  for (uint32_t i = 0; i < sizeof(charmap)/sizeof(charmap[0]); i++) {
    if (charmap[i] == 0) {
      continue;
    }
    res += ((double)charmap[i])/len  * (log2(len) - log2(charmap[i]));
  }
  //LOG_PRINT("Entropy exit\n");
  *ret = res;
  return ret;
}


static void handle_packet(pthread_t *threads, size_t thread_count, const uint8_t *packet, uint32_t len) {
  // TODO: Use a memory pool for this
  XDPPacketWrapper *data = malloc(sizeof(*data));
  data->packet = packet;
  data->length = len;
  pthread_create(&threads[ENTROPY_THREAD_ID], nullptr, calculate_entropy, data);
  pthread_create(&threads[0], nullptr, parse_protocols, data);
  

  double* entropy;
  struct Packet *pkt;


  pthread_join(threads[ENTROPY_THREAD_ID], (void**)&entropy);
  pthread_join(threads[0], (void**)&pkt);
  LOG_PRINT("Entropy: %f\n", *entropy);
  free(data);
  free(entropy);
}

static void handle_sigint(int sig) {
  LOG_ERROR("Caught sigint, cleaning up...\n");
  atomic_store(&run, false);
}

static inline int load_bpf_prog(int netif_id, struct xdp_program **bpf_prog) {
  char errbuff[1024];
  int err = 0;

  struct xdp_program *prog = xdp_program__open_file("build/pf.bpf.o", "xdp", nullptr);
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


static inline int cleanup_xdp_progs(int netif_id, struct xdp_program *prog){
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
    return ERROR_JUMP_UMEM_CLEANUP;
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

  return ERROR_JUMP_NO_ERROR;
}

enum ErrorJump fill_ring_fill(struct xsk_ring_prod *fill_ring){
  uint64_t *addrs = calloc(NUM_FRAMES, sizeof(uint64_t));
  if (!addrs) {
    LOG_ERROR("Failed to allocate memory via calloc: %s\n", strerror(errno));
    return ERROR_JUMP_SOCKET_CLEANUP;
  }

  for (size_t i = 0; i < NUM_FRAMES; i++) {
    addrs[i] = i * FRAME_SIZE;
  }

  uint32_t prod_idx = 0;

  size_t num_reserved = xsk_ring_prod__reserve(fill_ring, NUM_FRAMES, &prod_idx);
  if (num_reserved != NUM_FRAMES) {
    LOG_ERROR("Failed to reserve all fill ring entries (got %zu)\n", num_reserved);
    free(addrs);
    return ERROR_JUMP_ADDRS_CLEANUP;
  }

  for (size_t i = 0; i < NUM_FRAMES; i++) {
    *xsk_ring_prod__fill_addr(fill_ring, prod_idx + i) = addrs[i];
  }
  xsk_ring_prod__submit(fill_ring, NUM_FRAMES);
  free(addrs);
  return ERROR_JUMP_NO_ERROR;
}


static atomic_bool analyzer_fail = false;
void send_to_analyzer(unsigned int analyzer_if_id, int ansockfd, size_t payload_size, void *payload) {
  if (atomic_load(&analyzer_fail)) {
    return;
  }

  write(ansockfd, payload, payload_size);
}

static inline void packet_loop(pthread_t *threads, size_t thread_count, struct xsk_socket * xsk, struct xsk_ring_cons *rx_ring,  struct xsk_ring_prod *tx_ring, struct xsk_ring_prod *fill_ring, struct xsk_ring_cons *comp_ring) {
  struct pollfd fds = { .fd = xsk_socket__fd(xsk), .events = POLLIN };

  uint32_t rx_idx = 0;
  uint32_t rx_num_available = 0;
  const struct xdp_desc *desc = nullptr;
  struct xdp_desc *tx_desc = nullptr;
  const uint8_t *pkt = nullptr;
  uint32_t fill_idx;

  // RX cycle: 
  // Process -[MEM]-> Fill_Ring
  // Fill_Ring -> Kernel -[PACKET]-> Rx_Ring
  while (atomic_load(&run)) {
    int ret = poll(&fds, 1, 1000);
    if (ret < 0 && errno != EINTR) {
      LOG_ERROR("Failed to poll: %s\n", strerror(errno));
      break;
    }

    rx_num_available = xsk_ring_cons__peek(rx_ring, RING_SIZE, &rx_idx);
    if (rx_num_available == 0) {
      continue;
    }

    for (uint32_t i = 0; i < rx_num_available; i++) {
      desc = xsk_ring_cons__rx_desc(rx_ring, rx_idx + i);
      pkt = xsk_umem__get_data(umem_area, desc->addr);
      handle_packet(threads, THREAD_COUNT, pkt, desc->len);

      uint32_t tx_idx;
      if (xsk_ring_prod__reserve(tx_ring, 1, &tx_idx) == 1) {
        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(tx_ring, tx_idx);
        tx_desc->addr = desc->addr;
        tx_desc->len = desc->len;
        xsk_ring_prod__submit(tx_ring, 1);
      }
      // Tx ring full
      else if(xsk_ring_prod__reserve(fill_ring, 1, &fill_idx) == 1) {
        *xsk_ring_prod__fill_addr(fill_ring, fill_idx) = desc->addr; // <- Move from Rx to Fill
        xsk_ring_prod__submit(fill_ring, 1);
      }
      // BOTH Tx and Fill rings are full - drop
      else {
        LOG_ERROR("Both TX and Fill rings full, dropping packet\n");
      }
    }

    xsk_ring_cons__release(rx_ring, rx_num_available);
  }

  uint32_t comp_idx;
  const uint32_t comp_num_available = xsk_ring_cons__peek(comp_ring, RING_SIZE, &comp_idx);
  for (uint32_t i = 0; comp_num_available != 0 && i < comp_num_available; i++) {
    uint64_t addr = *xsk_ring_cons__comp_addr(comp_ring, comp_idx + i);
    uint32_t fill_idx;
    // Tx -> Fill
    if (xsk_ring_prod__reserve(fill_ring, 1, &fill_idx) == 1) {
      *xsk_ring_prod__fill_addr(fill_ring, fill_idx) = addr;
      xsk_ring_prod__submit(fill_ring, 1);
    }
    else {
      LOG_ERROR("Fill ring full, cannot recycle TX buffer\n");
    }
  }
  xsk_ring_cons__release(comp_ring, comp_num_available);
}


// TODO: Finish analyzer comms
static int analyzer_socket_init() {
  int ansockfd = socket(AF_INET, SOCK_DGRAM, 0);
  return ansockfd;
}

int main(int argc, char *argv[argc]) {
  if (argc < 3) {
    LOG_ERROR("Usage: %s [READ INTERFACE] [ANALYZER INTERFACE]", argv[0]);
    return EXIT_FAILURE;
  }


  const char *iface = argv[1];
  const char *analyzer_ifname = argv[1];

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

  unsigned int analyzer_if_id = if_nametoindex(analyzer_ifname);
  if (analyzer_if_id == 0) {
    LOG_ERROR("Failed to lookup analyzer network interface id: %s\n", strerror(errno));
    atomic_store(&analyzer_fail, true);
  }
  else {
    LOG_PRINT("Looked up analyzer netif_id: %u\n", netif_id);
  }


  struct xdp_program *prog = nullptr;
  err = load_bpf_prog(netif_id, &prog);

  if (err != EXIT_SUCCESS) {
    LOG_ERROR("Failed to load BPF program\n");
    return EXIT_FAILURE;
  }


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

  errjump = fill_ring_fill(&fill_ring);
  ERROR_JUMP(errjump);

  //pthread_t entropy_thread;
  //
  //pthread_create(entropy_thread, nullptr, entrop);

  signal(SIGINT, handle_sigint);

  errjump = mempool_init(PACKET_BUFFER_SIZE);
  ERROR_JUMP(errjump)

  packet_loop(threads, THREAD_COUNT, xsk, &rx_ring, &tx_ring, &fill_ring, &comp_ring);

  //int xsks_map_fd = bpf_obj_get(XSKS_MAP_PIN_PATH);
  //if (xsks_map_fd < 0) {
  //  LOG_ERROR("Failed to get xsks_map fd: %s\n", strerror(errno));
  //  goto cleanup;
  //}
  //LOG_PRINT("xsks_map_fd: %i\n", xsks_map_fd);

cleanup:

mempool_cleanup:
  mempool_deinit();

socket_cleanup:
  if (xsk != nullptr) {
    xsk_socket__delete(xsk);
    LOG_PRINT("Deleted XSK\n");
  }

umem_cleanup:
  xsk_umem__delete(umem);
  LOG_PRINT("Deleted umem\n");

umem_area_cleanup:
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

