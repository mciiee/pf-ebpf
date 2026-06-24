#include "ErrorJump.h"
#include "protocols.h"
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>


#include "log.h"

static void *mem = nullptr;
static size_t packet_capacity;
static atomic_ptrdiff_t last_free = 0;

//uint_fast8_t TRUE = false;
//uint_fast8_t FALSE = false;


uint64_t mempool_init(size_t packet_num) {
  packet_capacity = packet_num;
  mem = mmap(nullptr, packet_num * sizeof(struct Packet), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

  if (mem == MAP_FAILED) {
    LOG_ERROR("Failed to allocate mempool: %s\n", strerror(errno));
    return ERROR_JUMP_MEMPOOL_CLEANUP;
  }

  memset(mem, 0, packet_num * sizeof(struct Packet));

  return ERROR_JUMP_NO_ERROR;
}

void mempool_deinit(void) {
  if (mem == nullptr) {
    return;
  }
  munmap(mem, packet_capacity * sizeof(struct Packet));
}

void mempool_stats(void) {
  const struct Packet *mempool = mem;
  uint64_t packets_used;
  for (ptrdiff_t i = 0; i < packet_capacity; i++) {
    if (atomic_load(&mempool[i].used)) {
      packets_used++;
    }
  }
  printf("[MEMPOOL stats] last_free: %ld, used: %lu, free: %lu, total: %lu\n", last_free, packets_used, (uint64_t)(packet_capacity - packets_used), (uint64_t)packet_capacity);
}

struct Packet *packet_alloc(void) {
  struct Packet *mempool = mem;
  uint_fast8_t expected = false;
  ptrdiff_t lf = atomic_load(&last_free);

  for (size_t i = lf; i < packet_capacity; i++) {
    if (atomic_compare_exchange_strong(&mempool[i].used, &expected, false)) {
      return &mempool[i];
    }
    expected = false;
  }

  for (size_t i = 0; i < lf; i++) {
    if (atomic_compare_exchange_strong(&mempool[i].used, &expected, false)) {
      return &mempool[i];
    }
    expected = false;
  }

  return nullptr;
}

void packet_dealloc(struct Packet *packet) {
  atomic_store(&packet->used, false);
  atomic_store(&last_free,  packet - (struct Packet*)mem);
}
