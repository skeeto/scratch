/* XXTEA with 128-bit blocks
 * This is free and unencumbered software released into the public domain.
 */
#include <stdint.h>

static void
xxtea128_encrypt(const uint32_t k[4], uint32_t v[4])
{
    static const uint32_t t[] = {
        0x9e3779b9, 0x3c6ef372, 0xdaa66d2b, 0x78dde6e4, 0x1715609d,
        0xb54cda56, 0x5384540f, 0xf1bbcdc8, 0x8ff34781, 0x2e2ac13a,
        0xcc623af3, 0x6a99b4ac, 0x08d12e65, 0xa708a81e, 0x454021d7,
        0xe3779b90, 0x81af1549, 0x1fe68f02, 0xbe1e08bb,
    };
    for (int i = 0; i < 19; i++) {
        uint32_t e = t[i]>>2 & 3;
        v[0] += ((v[3]>>5 ^ v[1]<<2) + (v[1]>>3 ^ v[3]<<4)) ^
                ((t[i] ^ v[1]) + (k[0^e] ^ v[3]));
        v[1] += ((v[0]>>5 ^ v[2]<<2) + (v[2]>>3 ^ v[0]<<4)) ^
                ((t[i] ^ v[2]) + (k[1^e] ^ v[0]));
        v[2] += ((v[1]>>5 ^ v[3]<<2) + (v[3]>>3 ^ v[1]<<4)) ^
                ((t[i] ^ v[3]) + (k[2^e] ^ v[1]));
        v[3] += ((v[2]>>5 ^ v[0]<<2) + (v[0]>>3 ^ v[2]<<4)) ^
                ((t[i] ^ v[0]) + (k[3^e] ^ v[2]));
    }
}

static void
xxtea128_decrypt(const uint32_t k[4], uint32_t v[4])
{
    static const uint32_t t[] = {
        0xbe1e08bb, 0x1fe68f02, 0x81af1549, 0xe3779b90, 0x454021d7,
        0xa708a81e, 0x08d12e65, 0x6a99b4ac, 0xcc623af3, 0x2e2ac13a,
        0x8ff34781, 0xf1bbcdc8, 0x5384540f, 0xb54cda56, 0x1715609d,
        0x78dde6e4, 0xdaa66d2b, 0x3c6ef372, 0x9e3779b9,
    };
    for (int i = 0; i < 19; i++) {
        uint32_t e = (t[i] >> 2) & 3;
        v[3] -= ((v[2]>>5 ^ v[0]<<2) + (v[0]>>3 ^ v[2]<<4)) ^
                ((t[i] ^ v[0]) + (k[3^e] ^ v[2]));
        v[2] -= ((v[1]>>5 ^ v[3]<<2) + (v[3]>>3 ^ v[1]<<4)) ^
                ((t[i] ^ v[3]) + (k[2^e] ^ v[1]));
        v[1] -= ((v[0]>>5 ^ v[2]<<2) + (v[2]>>3 ^ v[0]<<4)) ^
                ((t[i] ^ v[2]) + (k[1^e] ^ v[0]));
        v[0] -= ((v[3]>>5 ^ v[1]<<2) + (v[1]>>3 ^ v[3]<<4)) ^
                ((t[i] ^ v[1]) + (k[0^e] ^ v[3]));
    }
}


#if TEST
#include <stdio.h>
#include <assert.h>

int
main(void)
{
    uint32_t k[4] = {0x8f469fe2, 0x67a66afa, 0xc850b407, 0x4904997c};
    uint32_t p[4] = {0xfbd85295, 0x7b025a60, 0xf88839f1, 0xb8d49cb4};
    uint32_t c[4] = {0x14f06ad6, 0x297afad1, 0xba87e0a7, 0xf90053fe};
    uint32_t t[4];
    t[0] = p[0]; t[1] = p[1]; t[2] = p[2]; t[3] = p[3];
    xxtea128_encrypt(k, t);
    assert(t[0] == c[0]); assert(t[1] == c[1]);
    assert(t[2] == c[2]); assert(t[3] == c[3]);
    xxtea128_decrypt(k, t);
    assert(t[0] == p[0]); assert(t[1] == p[1]);
    assert(t[2] == p[2]); assert(t[3] == p[3]);
}
#endif
