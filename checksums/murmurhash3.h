/* This is free and unencumbered software released into the public domain. */
#include <stdint.h>

static uint32_t
murmurhash3(const void *key, uint32_t len, uint32_t seed)
{
    uint32_t hash = seed;
    uint32_t nblocks = len / 4;
    const unsigned char *p = key;
    for (uint32_t i = 0; i < nblocks; i++) {
        uint32_t k = (uint32_t)p[i*4+0] <<  0 |
                     (uint32_t)p[i*4+1] <<  8 |
                     (uint32_t)p[i*4+2] << 16 |
                     (uint32_t)p[i*4+3] << 24;
        k *= UINT32_C(0xcc9e2d51);
        k = (k << 15) | (k >> 17);
        k *= UINT32_C(0x1b873593);
        hash ^= k;
        hash = ((hash << 13) | (hash >> 19)) * 5 + UINT32_C(0xe6546b64);
    }
    const unsigned char *tail = p + nblocks*4;
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3:
            k1 ^= tail[2] << 16;
        case 2:
            k1 ^= tail[1] << 8;
        case 1:
            k1 ^= tail[0];
            k1 *= UINT32_C(0xcc9e2d51);
            k1 = k1 << 15 | k1 >> 17;
            k1 *= UINT32_C(0x1b873593);
            hash ^= k1;
    }
    hash ^= len;
    hash ^= hash >> 16;
    hash *= UINT32_C(0x85ebca6b);
    hash ^= hash >> 13;
    hash *= UINT32_C(0xc2b2ae35);
    hash ^= hash >> 16;
    return hash;
}
