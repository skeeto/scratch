// Branchless UTF-8 encoder
//
// In my results, branching is ~30% faster for pure ASCII data, but
// branchless is ~40% faster if input has occasional non-ASCII bytes.
// Branchless is a lot slower at -O0 (not branchless in some cases).
//
// Ref: https://cceckman.com/writing/branchless-utf8-encoding/
// Ref: https://nullprogram.com/blog/2017/10/06/
// Ref: https://github.com/skeeto/branchless-utf8
// This is free and unencumbered software released into the public domain.

// Always writes four bytes, but returns the length to be kept (1-4).
int utf8encode(unsigned char *s, int cp)
{
    int utfmask[] = { 0xffffffff, 0x3fffffff, 0x3fffffff, 0x3fffffff };
    int lencode[] = { 0x00000000, 0x80c00000, 0x8080e000, 0x808080f0 };

    int len = 1 + (cp>0x7f) + (cp>0x7ff) + (cp>0xffff);
    int out = (((unsigned)cp << 24) & 0xff000000) |
              (((unsigned)cp << 10) & 0x003f0000) |
              (((unsigned)cp >>  4) & 0x00003f00) |
              (((unsigned)cp >> 18) & 0x0000003f);
    out &= utfmask[len-1];  // mask some of low byte if non-ASCII
    out |= lencode[len-1];  // inject length code

    out >>= (4 - len) * 8;
    s[0] = out >>  0;  // NOTE: optimized for little endian
    s[1] = out >>  8;
    s[2] = out >> 16;
    s[3] = out >> 24;
    return len;
}


#if TEST || BENCH
// $ cc -DTEST -o test utf8_branchless.c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ASSERT(c)   while (!(c)) *(volatile int *)0 = 0

static int utf8encode_validate(unsigned char *s, int c)
{
    switch ((c >= 0x80) + (c >= 0x800) + (c >= 0x10000)) {
    case 0: s[0] = 0x00 | ((c >>  0)     ); return 1;
    case 1: s[0] = 0xc0 | ((c >>  6)     );
            s[1] = 0x80 | ((c >>  0) & 63); return 2;
    case 2: s[0] = 0xe0 | ((c >> 12)     );
            s[1] = 0x80 | ((c >>  6) & 63);
            s[2] = 0x80 | ((c >>  0) & 63); return 3;
    case 3: s[0] = 0xf0 | ((c >> 18)     );
            s[1] = 0x80 | ((c >> 12) & 63);
            s[2] = 0x80 | ((c >>  6) & 63);
            s[3] = 0x80 | ((c >>  0) & 63); return 4;
    }
    ASSERT(0);
}

#if BENCH
// $ cc -DBENCH -o bench utf8_branchless.c
static int64_t rdtscp(void)
{
    uintptr_t lo, hi;
    asm volatile ("rdtscp" : "=a"(lo), "=d"(hi) : : "cx", "memory");
    return (int64_t)hi<<32 | lo;
}

static int randcp(uint64_t *rng)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    int range[32] = {  // mostly ASCII, occasional larger code points
        0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
        0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
        0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
        0x10ffff, 0xfff, 0xfff, 0x7ff, 0x7ff, 0x7ff, 0x7ff,
    };
    return (*rng>>32)*(1 + range[*rng>>27 & 31]) >> 32;
}

static void bench(void)
{
    #define GO(name, f) { \
        int64_t best = 0; \
        for (int n = 0; n < runs; n++) { \
            int64_t start = rdtscp(); \
            uint32_t sum = 0; \
            uint64_t rng = 1; \
            for (int i = 0; i < length; i++) { \
                int cp = randcp(&rng); \
                uint32_t out; \
                sum += f((unsigned char *)&out, cp); \
                sum += out; \
            } \
            volatile uint32_t sink = sum; (void)sink; \
            int64_t time = rdtscp() - start; \
            best = !best || time<best ? time : best; \
        } \
        printf(name "\t%.4g\tclocks/codepoint\n", (double)best/length); \
    }

    int runs   = 1<<4;
    int length = 1<<22;
    GO("branching",  utf8encode_validate);
    GO("branchless", utf8encode);
}

#else
static void bench(void) {}
#endif  // BENCH

int main(void)
{
    for (int cp = 0; cp <= 0x10ffff; cp++) {
        unsigned char want[4] = {0};
        unsigned char got[4] = {0};
        int wantlen = utf8encode_validate(want, cp);
        int gotlen = utf8encode(got, cp);
        ASSERT(wantlen == gotlen);
        ASSERT(!memcmp(want, got, wantlen));
    }
    bench();
}
#endif  // TEST
