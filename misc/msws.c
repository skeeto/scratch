/* Middle Square Weyl Sequence (PRNG)
 * Generator state may be seeded to any value.
 * Ref: https://arxiv.org/abs/1704.00358
 * This is free and unencumbered software released into the public domain.
 */
#include <stdint.h>

static uint32_t
msws32(uint64_t s[2])
{
    s[0] *= s[0];
    s[1] += 0xdc6b2b45361498ad;
    s[0] += s[1];
    s[0]  = s[0]<<32 | s[0]>>32;
    return s[0];
}

static uint64_t
msws64(uint64_t s[4])
{
    unsigned __int128 x = (unsigned __int128)s[1]<<64 | s[0];
    unsigned __int128 w = (unsigned __int128)s[3]<<64 | s[2];
    x *= x;
    w += (unsigned __int128)0x918fba1eff8e67e1<<64 | 0x8367589d496e8afd;
    x += w;
    s[0] = x >> 64; s[1] = x >>  0;
    s[2] = w >>  0; s[3] = w >> 64;
    return s[0];
}
