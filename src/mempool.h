#include <stddef.h>

int mempool_init(size_t pagenum);
void mempool_deinit(void);

void mempool_stats(void);

[[nodiscard("Leaking memory")]]
struct Packet *packet_alloc(void);
void packet_dealloc(struct Packet *packet);

