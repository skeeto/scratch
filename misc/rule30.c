/* Efficiently compute the center column of Rule 30
 * This is free and unencumbered software released into the public domain.
 */
#include <stdint.h>
#include <stdlib.h>

#define RULE 30

#define GEN_INIT {0, 0, 0}
struct gen { uint64_t len, cap, *bits; };

/* Return the next bit in the center column, or -1 when out of memory. */
static int
gen_next(struct gen *g)
{
    if (g->len == 0) {
        g->len = 1;
        g->cap = 64;
        g->bits = malloc(g->cap/8);
        if (!g->bits) {
            g->len = g->cap = 0;
            return -1;
        }
        g->bits[0] = 1;
        return 1;
    }

    /* Append two zero bits */
    if (g->cap < g->len + 2) {
        void *p = realloc(g->bits, g->cap*2/8);
        if (!p) {
            return -1;
        }
        g->cap *= 2;
        g->bits = p;
    }
    g->bits[g->len/64] &= ~(UINT64_C(1) << (g->len % 64));
    g->len++;
    g->bits[g->len/64] &= ~(UINT64_C(1) << (g->len % 64));
    g->len++;

    /* Slide window across bit array updating to the next line */
    int window = 0; /* prefill sliding window with two zero bits */
    uint64_t len = g->len;
    uint64_t *bits = g->bits;
    for (uint64_t i = 0; i < len; i++) {
        int nextbit = (int)(bits[i/64] >> (i % 64)) & 1;
        window = (window<<1 | nextbit) & 7;
        bits[i/64] &= ~(UINT64_C(1) << (i % 64)); /* clear */
        bits[i/64] |= ((RULE >> window) & UINT64_C(1)) << (i % 64);
    }
    return (bits[len/2/64] >> (len/2 % 64)) & 1;
}

#include <stdio.h>

int
main(void)
{
    struct gen g = GEN_INIT;
    static unsigned char buf[1<<12];
    long long count = 0;
    for (;;) {
        for (int i = 0; i < (int)sizeof(buf); i++) {
            unsigned acc = 0;
            for (int b = 0; b < 8; b++) {
                acc |= (unsigned)gen_next(&g) << b;
            }
            if (acc >> 8) {
                /* At least one result was -1 (OOM) */
                fwrite(buf, i, 1, stdout);
                return 0;
            }
            buf[i] = acc;
        }
        if (!fwrite(buf, sizeof(buf), 1, stdout)) { return 1; }
        if (fflush(stdout)) { return 1; }
        count += (int)sizeof(buf) * 8;
        fprintf(stderr, "%lld %.3fMB\n", count, g.cap/8388608.0);
    }
}
