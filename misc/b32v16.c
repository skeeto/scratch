/* b32v16: toy 32-bit block cipher using only 16-bit operations
 *
 * This toy Feistel cipher is 8 rounds of a computer-designed 16-bit
 * integer permutation. The key is 128 bits split into eight 16-bit
 * subkeys. Decryption is much slower than encryption and only the
 * "forward" direction was considered in its design.
 *
 * Test vectors:
 *   key = 0000 0000 0000 0000 0000 0000 0000 0000
 *   pt  = 00000000 00000001 00000002
 *   ct  = 45c44eba aab21e52 72557d55
 *   key = 0f00 0e01 0d02 0c03 0b04 0a05 0906 0807
 *   pt  = 00000000 deadbeef cafebabe
 *   ct  = 795ae0e3 f911bef9 7d95fe3b
 *
 * Ref: https://github.com/skeeto/hash-prospector
 *
 * This is free and unencumbered software released into the public domain.
 */
#include <stdint.h>

#define B32V16_HALFROUNDS 16

uint32_t
b32v16_encrypt(const uint16_t k[8], uint32_t b)
{
    uint16_t x = b;
    uint16_t y = b >> 16;
    for (int i = 1; i <= B32V16_HALFROUNDS; i++) {
        uint16_t t = x ^ k[i&7];
        t += t << 7; t ^= t >> 8;
        t += t << 3; t ^= t >> 2;
        t += t << 4; t ^= t >> 8;
        x = y;
        y ^= t + i;
    }
    return (uint32_t)y<<16 | x;
}

uint32_t
b32v16_decrypt(const uint16_t k[8], uint32_t b)
{
    uint16_t x = b;
    uint16_t y = b >> 16;
    for (int i = B32V16_HALFROUNDS; i > 0; i--) {
        uint16_t t = (y ^ x) - i;
        t ^= t >> 8;
        /* same as: t *= 0xf0f1U; */
        t += ((unsigned)t <<  4u) + ((unsigned)t <<  5u) +
             ((unsigned)t <<  6u) + ((unsigned)t <<  7u) +
             ((unsigned)t << 12u) + ((unsigned)t << 13u) +
             ((unsigned)t << 14u) + ((unsigned)t << 15u);
        t ^= t>>2 ^ t>>4 ^ t>>6 ^ t>>8 ^ t>>10 ^ t>>12 ^ t>>14;
        // same as: t *= 0x8e39U; */
        t += ((unsigned)t <<  3) + ((unsigned)t <<  4) +
             ((unsigned)t <<  5) + ((unsigned)t <<  9) +
             ((unsigned)t << 10) + ((unsigned)t << 11) + ((unsigned)t << 15);
        t ^= t >> 8;
        // same as: t *= 0x3f81U; */
        t += (t <<  7) + (t <<  8) + (t <<  9) + (t << 10) +
             (t << 11) + (t << 12) + (t << 13);
        t ^= k[i&7];
        y = x;
        x = t;
    }
    return (uint32_t)y<<16 | x;
}

#ifdef TEST
#include <stdio.h>

static uint32_t
u32(void)
{
    static uint64_t s = 1;
    return (s = s*0x243f6a8885a308d + 1) >> 32;
}

int
main(void)
{
    long errors = 0;

    for (long i = 0; i < 1L<<10; i++) {
        uint16_t key[8];
        for (int j = 0; j < 8; j++) {
            key[j] = u32() >> 16;
        }

        for (long j = 0; j < 1L<<12; j++) {
            uint32_t p = u32();
            uint32_t c = b32v16_encrypt(key, p);
            uint32_t d = b32v16_decrypt(key, c);
            if (p != d) {
                for (int k = 0; k < 8; k++) {
                    printf("%04x ", key[k]);
                }
                printf("%04x %04x %04x %04x %04x %04x %04x %04x "
                       "%08lx %08lx %08lx\n",
                       key[0], key[1], key[2], key[3],
                       key[4], key[5], key[6], key[7],
                       (long)p, (long)c, (long)d);
                errors += 1;
            }
        }
    }

    return errors != 0;
}
#endif /* TEST */
