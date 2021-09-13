// Middle Multiplicative Lagged Fibonacci Generator
// This is free and unencumbered software released into the public domain.
#include <stdint.h>

struct mmlfg {
    uint64_t s[15];
    int i, j;
};

void
mlfg_seed(struct mmlfg *s, uint64_t seed)
{
    for (int i = 0; i < 15; i++) {
        seed = seed*0x3243f6a8885a308d + 1111111111111111111;
        s->s[i] = (seed ^ seed>>31) | 1;
    }
    s->i = 14;
    s->j = 12;
}

uint64_t
mlfg_next(struct mmlfg *s)
{
    uint64_t lo, mi;
    #if defined(__GNUC__) || defined(__clang__)
        __uint128_t m = (__uint128_t)s->s[s->i] * s->s[s->j];
        mi = m >> 32;
        lo = m;
    #elif defined(_MSC_VER)
        uint64_t hi;
        lo = _umul128(s->s[s->i], s->s[s->j], &hi);
        mi = hi<<32 | lo>>32;
    #else
        uint64_t a = s->s[s->i], b = s->s[s->j];
        uint64_t r00 = (a & 0xffffffff) * (b & 0xffffffff);
        uint64_t r10 = (a >> 32       ) * (b & 0xffffffff);
        uint64_t r01 = (a & 0xffffffff) * (b >> 32       );
        uint64_t r11 = (a >> 32       ) * (b >> 32       );
        uint64_t cr = (r00 >> 32) + (r10 & 0xffffffff) + r01;
        uint64_t hi = (r10 >> 32) + (cr  >> 32       ) + r11;
                 lo = (cr  << 32) | (r00 & 0xffffffff);
        mi = hi<<32 | lo>>32;
    #endif
    s->s[s->i] = lo;
    s->i = s->i ? s->i-1 : 14;
    s->j = s->j ? s->j-1 : 14;
    return mi;
}


// Example
#include <stdio.h>

int
main(void)
{
    struct mmlfg s[4];
    for (int i = 0; i < 4; i++) {
        mlfg_seed(s+i, i);
    }

    for (int i = 0; i < 40; i++) {
        printf("%016llx %016llx %016llx %016llx\n",
                (unsigned long long)mlfg_next(s+0),
                (unsigned long long)mlfg_next(s+1),
                (unsigned long long)mlfg_next(s+2),
                (unsigned long long)mlfg_next(s+3));
    }
}
