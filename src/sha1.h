#ifndef SHA1_H
#define SHA1_H

/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#include <stdlib.h>
#include <stdint.h>

#define DIGEST_LEN 20

typedef struct {
  uint32_t state[5];
  uint32_t count[2];
  unsigned char buffer[64];
} sha1_context;

typedef sha1_context sha1_context_t;

sha1_context_t *sha1_context_init(void);
void sha1_update(sha1_context_t *context, const unsigned char *data, uint32_t len);
void sha1_finish(sha1_context_t *context, unsigned char digest[DIGEST_LEN]);
void sha1_compute(const char *str, int len, char hash_out[DIGEST_LEN]);
void sha1_context_free(sha1_context_t *ctx);

#endif /* SHA1_H */
