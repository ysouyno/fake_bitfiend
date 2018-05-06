#ifndef BYTE_STR_H
#define BYTE_STR_H

#include <stddef.h>

#if defined(_MSC_VER)
#pragma warning(disable: 4200)
#else
#endif

typedef struct byte_str {
  size_t size; // the size of str[]
  unsigned char str[];
} byte_str_t;

byte_str_t *byte_str_new(size_t size, const unsigned char *str);
void byte_str_free(byte_str_t *str);

#endif
