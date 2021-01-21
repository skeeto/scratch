/* "Tournament of the Towns" puzzle solver
 * Usage: cc -O towns.c && ./a.out
 * Ref: https://www.youtube.com/watch?v=El3InlRqiJs
 * Ref: https://rjlipton.wordpress.com/2016/02/21/coins-on-a-chessboard/
 * This is free and unencumbered software released into the public domain.
 */
#include <stdio.h>
#include <stdint.h>

/* The board is 8x8 just like a chessboard, so its state can be naturally
 * represented using a 64-bit integer. The bottom-left corner is zero, so
 * the initial board has value 1. A few bit manipulations handle all the
 * rules, and makes for an efficient hash table (i.e. seen()).
 */

static int
solved(uint64_t s)
{
    return !(s & 0x010307);
}

static uint64_t
mask_add(int n)
{
    return UINT64_C(1)<<(n+1) | UINT64_C(1)<<(n+8);
}

static uint64_t
mask_rem(int n)
{
    return UINT64_C(1)<<n & 0x007f7f7f7f7f7f7f;
}

static uint64_t
isvalid(uint64_t s, int n)
{
    return ((s & mask_add(n)) | (s & mask_rem(n))) == UINT64_C(1)<<n;
}

static uint64_t
apply(uint64_t s, int n)
{
    return s ^ (mask_add(n) | mask_rem(n));
}

#ifdef PRINT
static void
print(uint64_t s)
{
    for (int y = 7; y >= 0; y--) {
        for (int x = 0; x < 8; x++) {
            int i = y*8 + x;
            if (s>>i & 1) {
                putchar(isvalid(s, i) ? '$' : 'X');
            } else {
                putchar('-');
            }
        }
        putchar('\n');
    }
    putchar('\n');
}
#else
static void print(uint64_t s) { (void)s; }
#endif

static int
seen(uint64_t s)
{
    static uint64_t table[1L<<20];
    size_t n = sizeof(table)/sizeof(*table) - 1;
    uint64_t h = s * 0xc9ee54ebf3069939;
    h ^= h >> 32;
    for (size_t i = h; ; i++) {
        if (table[i&n] == 0) {
            table[i&n] = s;
            print(s);
            return 0;
        }
        if (table[i&n] == s) {
            return 1;
        }
    }
}

static int
solve(uint64_t s)
{
    if (solved(s)) {
        return 1;
    }

    if (seen(s)) {
        return 0;
    }

    for (int i = 0; i < 64; i++) {
        if (isvalid(s, i) && solve(apply(s, i))) {
            return 1;
        }
    }
    return 0;
}

int
main(void)
{
    if (!solve(1)) {
        puts("unsolvable");
    }
}
