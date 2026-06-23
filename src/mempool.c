#include "protocols.h"
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void *mem;
static size_t page_num;
static atomic_ptrdiff_t last_free = 0;


void *mempool_init(size_t pagenum) {
  
  page_num = pagenum;
  mem = mmap(nullptr, sysconf(_SC_PAGESIZE) * pagenum, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
  if (mem == MAP_FAILED) {
    return nullptr;
  }
  memset(mem, 0, pagenum * sysconf(_SC_PAGESIZE));

  return mem;
}

void mempool_deinit(void *mem) {
  munmap(mem, page_num * sysconf(_SC_PAGESIZE));
}

struct Packet *packet_alloc(size_t packet_num) {
  struct Packet *mempool = mem;
  const int page_size = sysconf(_SC_PAGESIZE);
  
  for (size_t i = last_free; i * sizeof(struct Packet) < page_num * page_size; i++) {
    if (atomic_load(&mempool[i].free)) {
      atomic_store(&mempool[i].free, false);
      return &mempool[i];
    }
  }

  for (size_t i = 0; i < last_free ; i++) {
    if (atomic_load(&mempool[i].free)) {
      atomic_store(&mempool[i].free, false);
      return &mempool[i];
    }
  }

  return nullptr;
}

void packet_dealloc(struct Packet *packet) {
  atomic_store(&packet->free, true);
  atomic_store(&last_free, (struct Packet*)mem - packet);
}
