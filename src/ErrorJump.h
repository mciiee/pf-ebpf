#ifndef ERRORJUMP_H
#define ERRORJUMP_H
#include <stdint.h>
enum ErrorJump: uint64_t {
  ERROR_JUMP_NO_ERROR = 0,
  ERROR_JUMP_UMEM_CLEANUP = 0x1,
  ERROR_JUMP_XDP_PROG_CLEANUP= 0x2
};
#endif
