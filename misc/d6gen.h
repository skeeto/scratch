/* d6gen: an entropy-preserving, high-quality 6-sided die roller
 *
 * Produces over 500 million rolls per second on conventional hardware. Uses
 * an internal Permuted Congruential Generator (PCG) to generate a 32-bit
 * value, from which it extracts up to 12 unbiased rolls. The PCG accepts a
 * 64-bit seed and has a period of 2^64, or ~211 quintillion rolls.
 *
 * Note: It's slower than generating a 32-bit number per roll, but it does
 * make the maximum use of each 32-bit result, hence entropy-preserving.
 *
 * This is free and unencumbered software released into the public domain.
 */
#ifndef D6GEN_H
#define D6GEN_H

#include <stdint.h>

#define D6GEN_INIT(seed64) {(seed64), 0, 0}
struct d6gen {
    uint64_t s;
    uint32_t r;
    int i;
};

/* Generate a single high-quality 6-sided die roll (1-6). */
static int
d6gen(struct d6gen *g)
{
    static const char t[] = {5, 5, 0, 1, 0, 4, 0, 1, 5, 5, 0, 4};
    for (;;) {
        if (!g->i) {
            /* 64-bit PCG producing a 32-bit result */
            g->s  = g->s*0x7c3c3267d015ceb5 + 1;
            g->r  = g->s >> 32;
            g->r ^= g->r >> 16;
            g->r *= 0x60857ba9;
            g->r ^= g->r >> 16;
            g->i  = sizeof(t) / sizeof(t[0]);
        }

        /* Determine valid range for this order of magnitude */
        int excess = t[--g->i];
        if (g->r < excess) {
            /* Out of range: discard and get a fresh 32-bit number */
            g->i = 0;
        } else {
            /* In range: trim unwanted excess and compute roll */
            g->r -= excess;
            int d = 1 + g->r%6;
            g->r /= 6;
            return d;
        }
    }
}

#endif
