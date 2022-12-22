/* This is free and unencumbered software released into the public domain. */
#include <stdint.h>

void
gimli(uint32_t s[12])
{
    for (int r = 24; r > 0; r--) {
        for (int c = 0; c < 4; c++) {
            uint32_t x = s[c+0];
            uint32_t y = s[c+4];
            uint32_t z = s[c+8];
            x = x << 24 | x >>  8;
            y = y <<  9 | y >> 23;
            s[c+8] = x ^ z<<1 ^ ((y&z) << 2);
            s[c+4] = y ^ x<<0 ^ ((x|z) << 1);
            s[c+0] = z ^ y<<0 ^ ((x&y) << 3);
        }

        uint32_t t;
        if ((r & 3) == 0) {
            t = s[0]; s[0] = s[1]; s[1] = t;
            t = s[2]; s[2] = s[3]; s[3] = t;
        }
        if ((r & 3) == 2) {
            t = s[0]; s[0] = s[2]; s[2] = t;
            t = s[1]; s[1] = s[3]; s[3] = t;
        }
        if ((r & 3) == 0) {
            s[0] ^= 0x9e377900 | r;
        }
    }
}
