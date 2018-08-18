/* Based on Dave Bollinger's Pixel Spaceships
 * http://davebollinger.org/works/pixelspaceships/
 * Usage:
 *   $ cc -O spaceship.c
 *   $ ./a.out > ship.pbm
 *   $ xdg-open ship.pbm
 */
#include <time.h>
#include <stdio.h>

/* Returns the pixel bit value for (x, y) for the given ship spec.
 * The image is 12x12 and the ship spec is a 32-bit value.
 */
static int
ship_sample(unsigned long spec, int x, int y)
{
    /* Each slot in the pattern is a specification for how that bit is
     * set given the ship specification. Each entry is 13 bits
     * partitioned like so:
     *
     * N LL AAAAA BBBBB
     *
     * AAAAA and BBBBB are 5-bit values referencing bits in the ship
     * specification. These may or may not be used depending on LL.
     *
     * LL is a 2-bit value indicating the "length" of the array stored
     * across AAAAA and BBBBB. It can be 0, 1, or 2.
     *
     * N is negation (e.g. AND vs. NAND operation).
     *
     * To compute the output, the bits referenced by AAAAA and BBBBB
     * are ANDed together and then NOTed according to N. When LL == 0,
     * the result of the AND is 1. This leads to two special cases:
     *
     * 0 00 xxxxx xxxxx => always 1
     * 1 00 xxxxx xxxxx => always 0
     */
    #define E2(neg, a, b) neg * 4096 + 2048 + a * 32 + b
    #define E1(neg, a)    neg * 4096 + 1024 + a
    #define E0(neg)       neg * 4096
    static const short pattern[12][6] = {
        {E0(1)   , E0(1)     , E0(1)      , E0(1)    , E1(1,0) , E1(1,1) },
        {E0(1)   , E0(1)     , E0(1)      , E1(1,0)  , E1(0,0) , E1(0,1) },
        {E0(1)   , E0(1)     , E0(1)      , E2(1,2,3), E1(0,2) , E0(0)   },
        {E0(1)   , E0(1)     , E1(1,3)    , E1(0,3)  , E1(0,4) , E0(0)   },
        {E0(1)   , E0(1)     , E2(1,5,7)  , E1(0,5)  , E1(0,6) , E0(0)   },
        {E0(1)   , E2(1,7,10), E1(0,7)    , E1(0,8)  , E1(0,9) , E0(0)   },
        {E1(1,10), E1(0,10)  , E1(0,11)   , E1(0,12) , E1(0,13), E1(0,14)},
        {E1(1,15), E1(0,15)  , E1(0,16)   , E1(0,17) , E1(0,18), E1(0,19)},
        {E1(1,20), E1(0,20)  , E1(0,21)   , E1(0,22) , E1(0,23), E1(0,24)},
        {E1(1,25), E1(0,25)  , E1(0,26)   , E1(0,27) , E1(0,28), E0(0)   },
        {E0(1)   , E1(1,25)  , E2(1,26,29), E1(0,29) , E1(0,30), E1(0,31)},
        {E0(1)   , E0(1)     , E0(1)      , E1(1,29) , E1(1,30), E1(1,31)}
    };
    #undef E0
    #undef E1
    #undef E2
    int v = pattern[y][x > 5 ? 11 - x : x];
    int r = 1;
    switch ((v >> 10) & 3) {
        case 2: r = r && ((spec >> (v >> 5 & 0x1f)) & 1); /* FALLTHROUGH */
        case 1: r = r && ((spec >> (v >> 0 & 0x1f)) & 1);
    }
    return v >> 12 ? !r : r;
}

static unsigned long
hash(unsigned long x)
{
    x ^= (x & 0xffffffffUL) >> 17;
    x *= 0xed5ad4bbUL;
    x ^= (x & 0xffffffffUL) >> 11;
    x *= 0xac4c1b51UL;
    x ^= (x & 0xffffffffUL) >> 15;
    x *= 0x31848babUL;
    x ^= (x & 0xffffffffUL) >> 14;
    return x & 0xffffffffUL;
}

int
main(void)
{
    int x, y;
    int scale = 16;
    unsigned long seed = hash(time(0));

    /* Render to PBM */
    printf("P1\n%d %d\n", 12 * scale, 12 * scale);
    for (y = 0; y < 12 * scale; y++) {
        for (x = 0; x < 12 * scale; x++) {
            putchar('0' + ship_sample(seed, x / scale, y / scale));
            putchar('\n');
        }
    }
    return 0;
}
