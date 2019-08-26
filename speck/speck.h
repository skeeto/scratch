/* C99 implementation of Speck128/128
 * This is free and unencumbered software released into the public domain.
 */
#ifndef SPECK_H
#define SPECK_H

#include <stdint.h>

struct speck {
    uint64_t k[32];
};

static void
speck_init(struct speck *ctx, uint64_t x, uint64_t y)
{
    ctx->k[0] = y;
    for (uint64_t i = 0; i < 31; i++) {
        x = x>>8 | x<<56;
        x += y;
        x ^= i;
        y = y<<3 | y>>61;
        y ^= x;
        ctx->k[i+1] = y;
    }
}

static void
speck_encrypt(const struct speck *ctx, uint64_t *px, uint64_t *py)
{
    uint64_t x = *px;
    uint64_t y = *py;
    for (int i = 0; i < 32; i++) {
        x = x>>8 | x<<56;
        x += y;
        x ^= ctx->k[i];
        y = y<<3 | y>>61;
        y ^= x;
    }
    *px = x;
    *py = y;
}

static void
speck_decrypt(const struct speck *ctx, uint64_t *px, uint64_t *py)
{
    uint64_t x = *px;
    uint64_t y = *py;
    for (int i = 31; i >= 0; i--) {
        y ^= x;
        y = y>>3 | y<<61;
        x ^= ctx->k[i];
        x -= y;
        x = x<<8 | x>>56;
    }
    *px = x;
    *py = y;
}

#endif
