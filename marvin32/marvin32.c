/* Marvin32 hash function
 * This is free and unencumbered software released into the public domain.
 */
#include <stddef.h>
#include <stdint.h>

static uint32_t
marvin32(const void *buf, size_t len, uint64_t key)
{
    uint32_t h0 = key >>  0;
    uint32_t h1 = key >> 32;
    size_t nblocks = len / 4;
    const unsigned char *p = buf;

    for (size_t i = 0; i < nblocks; i++) {
        uint32_t b = (uint32_t)p[0] <<  0 | (uint32_t)p[1] <<  8 |
                     (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
        h0 += b;
        h1 ^= h0; h0 = h0 << 20 | h0 >> 12;
        h0 += h1; h1 = h1 <<  9 | h1 >> 23;
        h1 ^= h0; h0 = h0 << 27 | h0 >>  5;
        h0 += h1; h1 = h1 << 19 | h1 >> 13;
        p += 4;
    }

    uint32_t t = 0x80;
    switch (len % 4) {
    case 3: t = t<<8 | p[2]; /* fallthrough */
    case 2: t = t<<8 | p[1]; /* fallthrough */
    case 1: t = t<<8 | p[0];
    }
    h0 += t;

    h1 ^= h0; h0 = h0 << 20 | h0 >> 12;
    h0 += h1; h1 = h1 <<  9 | h1 >> 23;
    h1 ^= h0; h0 = h0 << 27 | h0 >>  5;
    h0 += h1; h1 = h1 << 19 | h1 >> 13;

    h1 ^= h0; h0 = h0 << 20 | h0 >> 12;
    h0 += h1; h1 = h1 <<  9 | h1 >> 23;
    h1 ^= h0; h0 = h0 << 27 | h0 >>  5;
    h0 += h1; h1 = h1 << 19 | h1 >> 13;

    return h0 ^ h1;
}

#if 0
/* WARNING: DO NOT USE! This exists only for benchmarking purposes. */
static uint64_t
marvin64(const void *buf, size_t len, uint64_t key0, uint64_t key1)
{
    uint64_t h0 = key0;
    uint64_t h1 = key1;
    size_t nblocks = len / 8;
    const unsigned char *p = buf;

    for (size_t i = 0; i < nblocks; i++) {
        uint64_t b = (uint64_t)p[0] <<  0 | (uint64_t)p[1] <<  8 |
                     (uint64_t)p[2] << 16 | (uint64_t)p[3] << 24 |
                     (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 |
                     (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
        h0 += b;
        h1 ^= h0; h0 = h0 << 40 | h0 >> 24;
        h0 += h1; h1 = h1 << 19 | h1 >> 45;
        h1 ^= h0; h0 = h0 << 55 | h0 >>  9;
        h0 += h1; h1 = h1 << 39 | h1 >> 25;
        p += 8;
    }

    uint64_t t = 0x80;
    switch (len % 8) {
    case 7: t = t<<8 | p[6]; /* fallthrough */
    case 6: t = t<<8 | p[5]; /* fallthrough */
    case 5: t = t<<8 | p[4]; /* fallthrough */
    case 4: t = t<<8 | p[3]; /* fallthrough */
    case 3: t = t<<8 | p[2]; /* fallthrough */
    case 2: t = t<<8 | p[1]; /* fallthrough */
    case 1: t = t<<8 | p[0];
    }
    h0 += t;

    h1 ^= h0; h0 = h0 << 40 | h0 >> 24;
    h0 += h1; h1 = h1 << 19 | h1 >> 45;
    h1 ^= h0; h0 = h0 << 55 | h0 >>  9;
    h0 += h1; h1 = h1 << 39 | h1 >> 25;

    h1 ^= h0; h0 = h0 << 40 | h0 >> 24;
    h0 += h1; h1 = h1 << 19 | h1 >> 45;
    h1 ^= h0; h0 = h0 << 55 | h0 >>  9;
    h0 += h1; h1 = h1 << 39 | h1 >> 25;

    return h0 ^ h1;
}
#endif


#ifdef TEST
#include <stdio.h>

/* Usage: $ cc -DTEST -Og -g -fsanitize=address,undefined marvin32.c
 *        $ ./a.out
 */
int
main(void)
{
    static const struct {
        uint64_t seed;
        char buf[8];
        char len;
        uint64_t expect;
    } tests[] = {
        #define SEED0 0x004fb61a001bdbcc
        #define SEED1 0x804fb61a001bdbcc
        #define SEED2 0x804fb61a801bdbcc

        #define BUF0  ""
        #define BUF1  "\xaf"
        #define BUF2  "\xe7\x0f"
        #define BUF3  "\x37\xf4\x95"
        #define BUF4  "\x86\x42\xdc\x59"
        #define BUF5  "\x15\x3f\xb7\x98\x26"
        #define BUF6  "\x09\x32\xe6\x24\x6c\x47"
        #define BUF7  "\xab\x42\x7e\xa8\xd1\x0f\xc7"

        {SEED0, BUF0, 0, 0x30ed35c100cd3c7d},
        {SEED0, BUF1, 1, 0x48e73fc77d75ddc1},
        {SEED0, BUF2, 2, 0xb5f6e1fc485dbff8},
        {SEED0, BUF3, 3, 0xf0b07c789b8cf7e8},
        {SEED0, BUF4, 4, 0x7008f2e87e9cf556},
        {SEED0, BUF5, 5, 0xe6c08c6da2afa997},
        {SEED0, BUF6, 6, 0x6f04bf1a5ea24060},
        {SEED0, BUF7, 7, 0xe11847e4f0678c41},

        {SEED1, BUF0, 0, 0x10a9d5d3996fd65d},
        {SEED1, BUF1, 1, 0x68201f91960ebf91},
        {SEED1, BUF2, 2, 0x64b581631f6ab378},
        {SEED1, BUF3, 3, 0xe1f2dfa6e5131408},
        {SEED1, BUF4, 4, 0x36289d9654fb49f6},
        {SEED1, BUF5, 5, 0x0a06114b13464dbd},
        {SEED1, BUF6, 6, 0xd6dd5e40ad1bc2ed},
        {SEED1, BUF7, 7, 0xe203987dba252fb3},

        #define A     "\x00"
        #define B     "\xff"
        {SEED2, A,             1, 0xa37fb0da2ecae06c},
        {SEED2, B,             1, 0xfecef370701ae054},
        {SEED2, A B,           2, 0xa638e75700048880},
        {SEED2, B A,           2, 0xbdfb46d969730e2a},
        {SEED2, B A B,         3, 0x9d8577c0fe0d30bf},
        {SEED2, A B A,         3, 0x4f9fbdde15099497},
        {SEED2, A B A B,       4, 0x24eaa279d9a529ca},
        {SEED2, B A B A,       4, 0xd3bec7726b057943},
        {SEED2, B A B A B,     5, 0x920b62bbca3e0b72},
        {SEED2, A B A B A,     5, 0x1d7ddf9dfdf3c1bf},
        {SEED2, A B A B A B,   6, 0xec21276a17e821a5},
        {SEED2, B A B A B A,   6, 0x6911a53ca8c12254},
        {SEED2, B A B A B A B, 7, 0xfdfd187b1d3ce784},
        {SEED2, A B A B A B A, 7, 0x71876f2efb1b0ee8},
    };
    static const int ntests = sizeof(tests)/sizeof(*tests);

    int fails = 0;
    for (int i = 0; i < ntests; i++) {
        uint32_t r = marvin32(tests[i].buf, tests[i].len, tests[i].seed);
        uint32_t e = tests[i].expect ^ tests[i].expect>>32;
        if (r != e) {
            fails++;
            printf("FAIL: [%d] got 0x%08lx, want 0x%08lx (0x%016llx)\n",
                    i, (unsigned long)r, (unsigned long)e,
                    (unsigned long long)tests[i].expect);
        }
    }
    if (!fails) {
        puts("All tests passed");
    }
    return fails != 0;
}
#endif

#ifdef BENCH
#include <stdio.h>

/* Usage: $ cc -DBENCH -O3 marvin32.c
 *        $ pv -a /dev/zero | ./a.out
 */
int
main(void)
{
    static char buf[512][128];  /* 128-byte strings in batches of 512 */
    volatile uint32_t sink = 0;
    for (;;) {
        if (!fread(buf, sizeof(buf), 1, stdin)) return 1;
        uint32_t h = 0;
        for (int i = 0; i < (int)(sizeof(buf)/sizeof(*buf)); i++) {
            h += marvin32(buf[i], sizeof(*buf), -1);
        }
        sink += h;
    }
}
#endif
