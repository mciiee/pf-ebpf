#ifndef ANALYZER_MESSAGE_H
#define ANALYZER_MESSAGE_H
#include "protocols.h"
#include <stddef.h>
#include <stdint.h>

typedef struct AnalyzerMessage {
  size_t length;
  uint8_t *payload;
} AnalyzerMessage;

#endif
