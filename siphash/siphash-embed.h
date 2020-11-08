/* SipHash implementation in portable C
 * This is free and unencumbered software released into the public domain.
 * Ref: https://cr.yp.to/siphash/siphash-20120620.pdf
 */
#include <stddef.h>
#include <stdint.h>

static uint64_t
siphash(const void *buf, size_t len, uint64_t key0, uint64_t key1)
{
    uint64_t v0 = key0 ^ 0x736f6d6570736575;
    uint64_t v1 = key1 ^ 0x646f72616e646f6d;
    uint64_t v2 = key0 ^ 0x6c7967656e657261;
    uint64_t v3 = key1 ^ 0x7465646279746573;

    const unsigned char *p = buf;
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

    uint64_t m = (uint64_t)len << 56;
    switch (len % 8) {
    case 7: m |= (uint64_t)p[6] << 48; /* fallthrough */
    case 6: m |= (uint64_t)p[5] << 40; /* fallthrough */
    case 5: m |= (uint64_t)p[4] << 32; /* fallthrough */
    case 4: m |= (uint64_t)p[3] << 24; /* fallthrough */
    case 3: m |= (uint64_t)p[2] << 16; /* fallthrough */
    case 2: m |= (uint64_t)p[1] <<  8; /* fallthrough */
    case 1: m |= (uint64_t)p[0] <<  0; /* fallthrough */
    }
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

#ifdef TEST
#include <stdio.h>

int
main(void)
{
    uint64_t key[2] = {
        0x0706050403020100, 0x0f0e0d0c0b0a0908,
    };
    unsigned char buf[15] = {
        0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    };
    if (siphash(buf, sizeof(buf), key[0], key[1]) != 0xa129ca6149be45e5) {
        puts("FAILURE");
        return 1;
    }
    puts("SUCCESS");
    return 0;
}
#endif
