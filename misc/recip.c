// Shanks Reciprocals of Prime Numbers (number of figures in the period)
//   $ cc -fopenmp -Wl,--stack,16777216 -O3 -o recip recip.c
//   $ ./recip >recip.txt
// Ref: https://www.youtube.com/watch?v=DmfxIhmGPP4
#include <stdio.h>
#include <stdint.h>

#define MAXN  1000000

static int32_t
recip_len(int32_t n)
{
    int32_t r = 1;
    while (r < n) r *= 10;  // skip leading zeros

    int32_t len = 0;
    uint32_t seen[(MAXN*10 + 31)/32] = {0};
    for (; r; len++) {
        while (r < n) {
            r *= 10;
            len++;
        }

        if (seen[r>>5] & (1 << (r&31))) {
            break;
        }
        seen[r>>5] |= 1 << (r&31);

        r = 10*(r - n*(r / n));
    }
    return len;
}

int main(void)
{
    uint32_t sieve[(MAXN + 31)/32] = {0};
    for (int32_t n = 2; n < MAXN; n++) {
        if (!(sieve[n>>5] & (UINT32_C(1) << (n&31)))) {
            for (int32_t i = 2*n; i < MAXN; i += n) {
                sieve[i>>5] |= UINT32_C(1) << (i&31);
            }
        }
    }

    int32_t lens[MAXN];
    #pragma omp parallel for schedule(dynamic)
    for (int32_t n = 2; n < MAXN; n++) {
        if (!(sieve[n>>5] & (UINT32_C(1) << (n&31)))) {
            lens[n] = recip_len(n);
        }
    }

    int32_t c = 0;
    for (int32_t n = 2; n < MAXN; n++) {
        if (!(sieve[n>>5] & (UINT32_C(1) << (n&31)))) {
            printf("%6ld%7ld %s", (long)n, (long)lens[n],
                   c++%5 == 4 ? "\n" : "| ");
        }
    }
    putchar('\n');
}
