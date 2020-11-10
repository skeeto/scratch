/* This is free and unencumbered software released into the public domain. */
#include <stddef.h>
#include <stdint.h>

#define SIPHASH_KEYLEN 16
#define SIPHASH_OUTLEN 16

struct siphash {
    uint64_t v0, v1, v2, v3;
    uint64_t m;
};

void     siphash_init(struct siphash *, const void *key);
void     siphash_update(struct siphash *, const void *, size_t);
uint64_t siphash_final(const struct siphash *);

void     siphash_init128(struct siphash *, const void *key);
void     siphash_final128(const struct siphash *, void *digest);
