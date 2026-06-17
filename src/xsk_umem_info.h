#ifndef XSK_UMEM_INFO_H
#define XSK_UMEM_INFO_H

#include <xdp/xsk.h>

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};
#endif
