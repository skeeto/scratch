/* chunky64: a chunky, fast, 64-bit, portable, keyed hash function
 * This is free and unencumbered software released into the public domain.
 */
#include <stddef.h>
#include <stdint.h>

static uint64_t
chunky64(const void *buf, size_t len, uint64_t key)
{
    size_t nblocks = len / 8;
    const unsigned char *p = buf;
    uint64_t h = 0x637f6e65916dff18 ^ key;

    for (size_t i = 0; i < nblocks; i++) {
        h ^= (uint64_t)p[0] <<  0 | (uint64_t)p[1] <<  8 |
             (uint64_t)p[2] << 16 | (uint64_t)p[3] << 24 |
             (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 |
             (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
        h *= 0xbf58476d1ce4e5b9;
        p += 8;
    }

    uint64_t last = len & 0xff;
    switch (len % 8) {
        case 7: last |= (uint64_t)p[6] << 56; /* fallthrough */
        case 6: last |= (uint64_t)p[5] << 48; /* fallthrough */
        case 5: last |= (uint64_t)p[4] << 40; /* fallthrough */
        case 4: last |= (uint64_t)p[3] << 32; /* fallthrough */
        case 3: last |= (uint64_t)p[2] << 24; /* fallthrough */
        case 2: last |= (uint64_t)p[1] << 16; /* fallthrough */
        case 1: last |= (uint64_t)p[0] <<  8;
                h ^= last;
                h *= 0xd6e8feb86659fd93;
    }

    h ^= h >> 32;
    return h ^ key;
}
