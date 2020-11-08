/* This is free and unencumbered software released into the public domain. */
#include <stddef.h>
#include <stdint.h>

struct siphash {
    uint64_t v0, v1, v2, v3;
    uint64_t m;
    uint64_t len;
};

void     siphash_init(struct siphash *, uint64_t key0, uint64_t key1);
void     siphash_update(struct siphash *, const void *, size_t);
uint64_t siphash_final(const struct siphash *);
