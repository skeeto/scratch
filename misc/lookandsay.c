// Binary Look-and-say Iterator
//   $ cc -O3 -march=native -fopenmp -o lookandsay lookandsay.c
//   $ ./lookandsay
//
// Computes the ratio of 1s to 0s at each iteration, demonstrating that
// it converges to 1.665727... rather than 5/3.
//
// Ref: https://www.youtube.com/watch?v=EGoRJePORHs
// This is free and unencumbered software released into the public domain.
#include <stdio.h>

// A look-and-say iterator computing blocks of output. The target
// iteration is limited to 248, well beyond any reasonable amount of
// computing power.
struct lns {
    int target;
    int top;
    unsigned char stack[248];
};
#define LNS_INIT(target) {(target)-1, 0, {8}}

// A small block of look-and-say output.
struct lns_block {
    const char *buf;
    int len;
};

// Compute the next block of output. A zero-length block indicates the
// end of the output. Otherwise the length is 1-6.
static struct lns_block
lns_next(struct lns *s)
{
    // Special, compact lookup table for binary look-and-say. The first
    // 8 bytes are overlapping output strings, and then each 4 bytes is
    // a look-and-say block (offset, length, next[0], next[1]).
    static const unsigned char lns[] = {
        49, 49, 49, 49, 48, 48,  0,  0,
         0,  1, 12,  0,  0,  2, 16,  8,
         3,  2, 24,  0,  2,  3, 16, 20,
         1,  4, 28,  0,  0,  5, 32, 20,
         3,  3, 40,  0,  2,  4, 16, 36,
         1,  5, 44,  0,  0,  6, 32, 36
    };
    struct lns_block r = {(const char *)lns, 0};
    while (s->top >= 0) {
        int n = s->stack[s->top] & 252;
        int i = s->stack[s->top] & 3;
        if (s->top == s->target) {
            r.buf += lns[n+0];
            r.len  = lns[n+1];
            s->top--;
            return r;
        } else if (i < 2 && lns[n+i+2]) {
            s->stack[s->top]++;
            s->stack[++s->top] = lns[n+i+2];
        } else {
            s->top--;
        }
    }
    return r;
}

int
main(void)
{
    #pragma omp parallel for schedule(dynamic)
    for (int i = 3; i <= 64; i++) {
        long long hist[2] = {0, 0};
        struct lns lns = LNS_INIT(i);
        struct lns_block b;
        do {
            b = lns_next(&lns);
            for (int i = 0; i < b.len; i++) {
                hist[b.buf[i]-'0']++;
            }
        } while (b.len);
        double ratio = (double)hist[1] / hist[0];
        printf("%-3d %16lld / %-16lld = %.17g\n", i, hist[1], hist[0], ratio);
    }
}
