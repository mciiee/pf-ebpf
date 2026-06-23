#include <stddef.h>

[[nodiscard("Memory-mapped page")]]
void *mempool_init(size_t pagenum);
void mempool_deinit(void *mem);


[[nodiscard("Leaking memory")]]
struct Packet *packet_alloc(size_t packet_num);
void packet_dealloc(struct Packet *packet);

