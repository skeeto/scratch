/* This is free and unencumbered software released into the public domain. */
#include "siphash.h"

void
siphash_init(struct siphash *s, uint64_t key0, uint64_t key1)
{
    s->v0 = key0 ^ 0x736f6d6570736575;
    s->v1 = key1 ^ 0x646f72616e646f6d;
    s->v2 = key0 ^ 0x6c7967656e657261;
    s->v3 = key1 ^ 0x7465646279746573;
    s->m = 0;
}

void
siphash_update(struct siphash *s, const void *buf, size_t len)
{
    uint64_t v0 = s->v0;
    uint64_t v1 = s->v1;
    uint64_t v2 = s->v2;
    uint64_t v3 = s->v3;
    const unsigned char *p = buf;

    /* Absorb bytes into block left open from previous update. */
    for (; len && (s->m>>56 & 7); len--, s->m += 0x0100000000000000, p++) {
        int i = s->m>>56 & 7;
        if (i < 7) {
            s->m |= (uint64_t)*p << (i*8);
        } else {
            uint64_t m = (uint64_t)*p<<56 | (s->m & 0x00ffffffffffffff);
            v3 ^= m;
            v0 += v1; v1 = v1<<13 | v1>>51; v1 ^= v0; v0 = v0<<32 | v0>>32;
            v2 += v3; v3 = v3<<16 | v3>>48; v3 ^= v2;
            v0 += v3; v3 = v3<<21 | v3>>43; v3 ^= v0;
            v2 += v1; v1 = v1<<17 | v1>>47; v1 ^= v2; v2 = v2<<32 | v2>>32;
            v0 += v1; v1 = v1<<13 | v1>>51; v1 ^= v0; v0 = v0<<32 | v0>>32;
            v2 += v3; v3 = v3<<16 | v3>>48; v3 ^= v2;
            v0 += v3; v3 = v3<<21 | v3>>43; v3 ^= v0;
            v2 += v1; v1 = v1<<17 | v1>>47; v1 ^= v2; v2 = v2<<32 | v2>>32;
            v0 ^= m;
            s->m &= 0xff00000000000000;
        }
    }

    for (size_t i = 0; i < len/8; i++) {
        uint64_t m = (uint64_t)p[7] << 56 | (uint64_t)p[6] << 48 |
                     (uint64_t)p[5] << 40 | (uint64_t)p[4] << 32 |
                     (uint64_t)p[3] << 24 | (uint64_t)p[2] << 16 |
                     (uint64_t)p[1] <<  8 | (uint64_t)p[0] <<  0;
        v3 ^= m;
        v0 += v1; v1 = v1<<13 | v1>>51; v1 ^= v0; v0 = v0<<32 | v0>>32;
        v2 += v3; v3 = v3<<16 | v3>>48; v3 ^= v2;
        v0 += v3; v3 = v3<<21 | v3>>43; v3 ^= v0;
        v2 += v1; v1 = v1<<17 | v1>>47; v1 ^= v2; v2 = v2<<32 | v2>>32;
        v0 += v1; v1 = v1<<13 | v1>>51; v1 ^= v0; v0 = v0<<32 | v0>>32;
        v2 += v3; v3 = v3<<16 | v3>>48; v3 ^= v2;
        v0 += v3; v3 = v3<<21 | v3>>43; v3 ^= v0;
        v2 += v1; v1 = v1<<17 | v1>>47; v1 ^= v2; v2 = v2<<32 | v2>>32;
        v0 ^= m;
        p += 8;
    }

    /* Copy bytes into partial block for next update. */
    s->m += (uint64_t)len << 56;
    switch (len & 7) {
    case 7: s->m |= (uint64_t)p[6] << 48; /* fallthrough */
    case 6: s->m |= (uint64_t)p[5] << 40; /* fallthrough */
    case 5: s->m |= (uint64_t)p[4] << 32; /* fallthrough */
    case 4: s->m |= (uint64_t)p[3] << 24; /* fallthrough */
    case 3: s->m |= (uint64_t)p[2] << 16; /* fallthrough */
    case 2: s->m |= (uint64_t)p[1] <<  8; /* fallthrough */
    case 1: s->m |= (uint64_t)p[0] <<  0; /* fallthrough */
    }

    s->v0 = v0;
    s->v1 = v1;
    s->v2 = v2;
    s->v3 = v3;
}

uint64_t
siphash_final(const struct siphash *s)
{
    uint64_t v0 = s->v0;
    uint64_t v1 = s->v1;
    uint64_t v2 = s->v2;
    uint64_t v3 = s->v3;

    v3 ^= s->m;
    v0 += v1; v1 = v1<<13 | v1>>51; v1 ^= v0; v0 = v0<<32 | v0>>32;
    v2 += v3; v3 = v3<<16 | v3>>48; v3 ^= v2;
    v0 += v3; v3 = v3<<21 | v3>>43; v3 ^= v0;
    v2 += v1; v1 = v1<<17 | v1>>47; v1 ^= v2; v2 = v2<<32 | v2>>32;
    v0 += v1; v1 = v1<<13 | v1>>51; v1 ^= v0; v0 = v0<<32 | v0>>32;
    v2 += v3; v3 = v3<<16 | v3>>48; v3 ^= v2;
    v0 += v3; v3 = v3<<21 | v3>>43; v3 ^= v0;
    v2 += v1; v1 = v1<<17 | v1>>47; v1 ^= v2; v2 = v2<<32 | v2>>32;
    v0 ^= s->m;

    v2 ^= 0xff;
    v0 += v1; v1 = v1<<13 | v1>>51; v1 ^= v0; v0 = v0<<32 | v0>>32;
    v2 += v3; v3 = v3<<16 | v3>>48; v3 ^= v2;
    v0 += v3; v3 = v3<<21 | v3>>43; v3 ^= v0;
    v2 += v1; v1 = v1<<17 | v1>>47; v1 ^= v2; v2 = v2<<32 | v2>>32;
    v0 += v1; v1 = v1<<13 | v1>>51; v1 ^= v0; v0 = v0<<32 | v0>>32;
    v2 += v3; v3 = v3<<16 | v3>>48; v3 ^= v2;
    v0 += v3; v3 = v3<<21 | v3>>43; v3 ^= v0;
    v2 += v1; v1 = v1<<17 | v1>>47; v1 ^= v2; v2 = v2<<32 | v2>>32;
    v0 += v1; v1 = v1<<13 | v1>>51; v1 ^= v0; v0 = v0<<32 | v0>>32;
    v2 += v3; v3 = v3<<16 | v3>>48; v3 ^= v2;
    v0 += v3; v3 = v3<<21 | v3>>43; v3 ^= v0;
    v2 += v1; v1 = v1<<17 | v1>>47; v1 ^= v2; v2 = v2<<32 | v2>>32;
    v0 += v1; v1 = v1<<13 | v1>>51; v1 ^= v0; v0 = v0<<32 | v0>>32;
    v2 += v3; v3 = v3<<16 | v3>>48; v3 ^= v2;
    v0 += v3; v3 = v3<<21 | v3>>43; v3 ^= v0;
    v2 += v1; v1 = v1<<17 | v1>>47; v1 ^= v2; v2 = v2<<32 | v2>>32;
    return v0 ^ v1 ^ v2 ^ v3;
}
