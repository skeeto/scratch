// Lights Out 5x5 bitboard implementation with optimal solver
// This is free and unencumbered software released into the public domain.

// Press light selection s on 5x5 board b.
static int
lightsout_apply(int b, int s)
{
    static const int flips[5][32] = {
        {0x0000000, 0x0000023, 0x0000047, 0x0000064,
         0x000008e, 0x00000ad, 0x00000c9, 0x00000ea,
         0x000011c, 0x000013f, 0x000015b, 0x0000178,
         0x0000192, 0x00001b1, 0x00001d5, 0x00001f6,
         0x0000218, 0x000023b, 0x000025f, 0x000027c,
         0x0000296, 0x00002b5, 0x00002d1, 0x00002f2,
         0x0000304, 0x0000327, 0x0000343, 0x0000360,
         0x000038a, 0x00003a9, 0x00003cd, 0x00003ee},
        {0x0000000, 0x0000461, 0x00008e2, 0x0000c83,
         0x00011c4, 0x00015a5, 0x0001926, 0x0001d47,
         0x0002388, 0x00027e9, 0x0002b6a, 0x0002f0b,
         0x000324c, 0x000362d, 0x0003aae, 0x0003ecf,
         0x0004310, 0x0004771, 0x0004bf2, 0x0004f93,
         0x00052d4, 0x00056b5, 0x0005a36, 0x0005e57,
         0x0006098, 0x00064f9, 0x000687a, 0x0006c1b,
         0x000715c, 0x000753d, 0x00079be, 0x0007ddf},
        {0x0000000, 0x0008c20, 0x0011c40, 0x0019060,
         0x0023880, 0x002b4a0, 0x00324c0, 0x003a8e0,
         0x0047100, 0x004fd20, 0x0056d40, 0x005e160,
         0x0064980, 0x006c5a0, 0x00755c0, 0x007d9e0,
         0x0086200, 0x008ee20, 0x0097e40, 0x009f260,
         0x00a5a80, 0x00ad6a0, 0x00b46c0, 0x00bcae0,
         0x00c1300, 0x00c9f20, 0x00d0f40, 0x00d8360,
         0x00e2b80, 0x00ea7a0, 0x00f37c0, 0x00fbbe0},
        {0x0000000, 0x0118400, 0x0238800, 0x0320c00,
         0x0471000, 0x0569400, 0x0649800, 0x0751c00,
         0x08e2000, 0x09fa400, 0x0ada800, 0x0bc2c00,
         0x0c93000, 0x0d8b400, 0x0eab800, 0x0fb3c00,
         0x10c4000, 0x11dc400, 0x12fc800, 0x13e4c00,
         0x14b5000, 0x15ad400, 0x168d800, 0x1795c00,
         0x1826000, 0x193e400, 0x1a1e800, 0x1b06c00,
         0x1c57000, 0x1d4f400, 0x1e6f800, 0x1f77c00},
        {0x0000000, 0x0308000, 0x0710000, 0x0418000,
         0x0e20000, 0x0d28000, 0x0930000, 0x0a38000,
         0x1c40000, 0x1f48000, 0x1b50000, 0x1858000,
         0x1260000, 0x1168000, 0x1570000, 0x1678000,
         0x1880000, 0x1b88000, 0x1f90000, 0x1c98000,
         0x16a0000, 0x15a8000, 0x11b0000, 0x12b8000,
         0x04c0000, 0x07c8000, 0x03d0000, 0x00d8000,
         0x0ae0000, 0x09e8000, 0x0df0000, 0x0ef8000}
    };
    b ^= flips[0][s       & 0x1f];
    b ^= flips[1][s >>  5 & 0x1f];
    b ^= flips[2][s >> 10 & 0x1f];
    b ^= flips[3][s >> 15 & 0x1f];
    b ^= flips[4][s >> 20       ];
    return b;
}

// Populate an exhaustive 32MiB optimal solution table for a 5x5 board.
// This table essentially inverts lightsout_apply.
static void
lightsout_init(int t[1L<<23])
{
    #if __GNUC__
    #  define POPCOUNT32(x) __builtin_popcount(x)
    #elif _MSC_VER
    #  define POPCOUNT32(x) __popcnt(x)
    #endif
    for (int i = 0; i < 0x800000; i++) {
        t[i] = -1;
    }
    for (int s = 0; s < 0x2000000; s++) {
        int i = lightsout_apply(0, s) >> 2;
        if (POPCOUNT32(s) < POPCOUNT32(t[i])) {
            t[i] = s;
        }
    }
}

// Lookup the optimal solution for a 5x5 board, or -1 if no solution.
static int
lightsout_lookup(const int t[1L<<23], int b)
{
    int i = b >> 2;
    return lightsout_apply(0, t[i]) == b ? t[i] : -1;
}


#ifdef TEST
#include <stdio.h>

// Test against an independent implementation of lightsout_apply.
static int
slow_apply(int b, int s)
{
    for (int i = 0; i < 25; i++) {
        if (s>>i & 1) {
            int x = i % 5, y = i / 5;
            /*      */ b ^= 1 << ((y + 0)*5 + x + 0);
            if (y < 4) b ^= 1 << ((y + 1)*5 + x + 0);
            if (y > 0) b ^= 1 << ((y - 1)*5 + x + 0);
            if (x < 4) b ^= 1 << ((y + 0)*5 + x + 1);
            if (x > 0) b ^= 1 << ((y + 0)*5 + x - 1);
        }
    }
    return b;
}

static void
print(int b)
{
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            putchar("-X"[b>>(y*5+x)&1]);
        }
        putchar('\n');
    }
}

int
main(void)
{
    static int solutions[1L<<23];
    lightsout_init(solutions);

    long fails = 0;
    for (int s = 0; s < 1<<25; s++) {
        int b = slow_apply(0, s);
        int s = lightsout_lookup(solutions, b);
        if (s == -1 || slow_apply(0, s) != b) {
            print(s); puts("ERROR");
            print(b); puts("=====");
            fails++;
        }
        if (POPCOUNT32(s) > POPCOUNT32(s)) {
            print(s); puts("UNOPT");
            print(b); puts("=====");
            fails++;
        }
    }

    int impossible = 0x1800000;
    if (lightsout_lookup(solutions, impossible) != -1) {
        print(impossible); puts("INVLD");
        fails++;
    }

    if (fails) {
        return 1;
    }
    puts("All tests pass.");
    return 0;
}
#endif
