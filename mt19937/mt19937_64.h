// This is free and unencumbered software released into the public domain.
#ifndef MT19937_64_H
#define MT19937_64_H

#ifndef MT19937_64_API
#  define MT19937_64_API static
#endif

#include <stdint.h>

struct mt19937_64 {
    uint64_t v[312];
    int i;
};

MT19937_64_API void     mt19937_64_init(struct mt19937_64 *, uint64_t seed);
MT19937_64_API uint64_t mt19937_64_next(struct mt19937_64 *);


#ifdef MT19937_64_IMPLEMENTATION

MT19937_64_API
void
mt19937_64_init(struct mt19937_64 *mt, uint64_t seed)
{
    mt->i = 312;
    mt->v[0] = seed;
    for (int i = 1; i < 312; i++) {
        mt->v[i] = 0x5851f42d4c957f2dU * (mt->v[i-1] ^ (mt->v[i-1] >> 62)) + i;
    }
}

MT19937_64_API
uint64_t
mt19937_64_next(struct mt19937_64 *mt)
{
    if (mt->i >= 312) {
        for (int i = 0; i < 312; i++) {
            uint64_t x = (mt->v[ i       ] & 0xffffffff80000000U) +
                         (mt->v[(i+1)%312] & 0x000000007fffffffU);
            uint64_t a = (x >> 1) ^ ((x & 1) * 0xb5026f5aa96619e9U);
            mt->v[i] = mt->v[(i+156)%312] ^ a;
        }
        mt->i = 0;
    }
    uint64_t y = mt->v[mt->i++];
    y = y ^ (y >> 29 & 0x5555555555555555U);
    y = y ^ (y << 17 & 0x71d67fffeda60000U);
    y = y ^ (y << 37 & 0xfff7eee000000000U);
    y = y ^ (y >> 43                      );
    return y;
}

#endif // MT19937_64_IMPLEMENTATION
#endif // MT19937_64_H
