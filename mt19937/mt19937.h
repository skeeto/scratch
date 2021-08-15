// This is free and unencumbered software released into the public domain.
#ifndef MT19937_H
#define MT19937_H

#ifndef MT19937_API
#  define MT19937_API static
#endif

#include <stdint.h>

struct mt19937 {
    uint32_t v[624];
    int i;
};

MT19937_API void     mt19937_init(struct mt19937 *, uint32_t seed);
MT19937_API uint32_t mt19937_next(struct mt19937 *);


#ifdef MT19937_IMPLEMENTATION

MT19937_API
void
mt19937_init(struct mt19937 *mt, uint32_t seed)
{
    mt->i = 624;
    mt->v[0] = seed;
    for (int i = 1; i < 624; i++) {
        mt->v[i] = 0x6c078965U * (mt->v[i-1] ^ (mt->v[i-1] >> 30)) + i;
    }
}

MT19937_API
uint32_t
mt19937_next(struct mt19937 *mt)
{
    if (mt->i >= 624) {
        for (int i = 0; i < 624; i++) {
            uint32_t x = (mt->v[ i       ] & 0x80000000U) +
                         (mt->v[(i+1)%624] & 0x7fffffffU);
            uint32_t a = (x >> 1) ^ ((x & 1) * 0x9908b0dfU);
            mt->v[i] = mt->v[(i+397)%624] ^ a;
        }
        mt->i = 0;
    }
    uint32_t y = mt->v[mt->i++];
    y = y ^ (y >> 11              );
    y = y ^ (y <<  7 & 0x9d2c5680U);
    y = y ^ (y << 15 & 0xefc60000U);
    y = y ^ (y >> 18              );
    return y;
}

#endif // MT19937_IMPLEMENTATION
#endif // MT19937_H
