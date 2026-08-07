/* Refind the counterexample to Polya's conjecture (1919).
 *
 * Conjecture: for all n >= 2, at least half the integers in [1,n] have
 * an odd number of prime factors (with multiplicity). Equivalently,
 * L(n) = sum of lambda(k) for k in [1,n] satisfies L(n) <= 0, where
 * lambda is the Liouville function.
 *
 * Believed for ~40 years, implies things as strong as RH, and false:
 * disproved abstractly by Haselgrove (1958), minimal counterexample
 * n = 906,150,257 found by Tanaka (1980). This program refinds it
 * from scratch with a segmented sieve. The point: a "verified for
 * hundreds of millions of cases" conjecture with real heuristic
 * appeal can still be false, and a laptop can find the witness.
 *
 * Usage: cc -O2 -o polya polya.c && ./polya
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define LIMIT   1000000000LL
#define SEGLEN  (1 << 20)

int main(void)
{
    /* primes up to sqrt(LIMIT) ~ 31623 */
    enum { SQRT = 31623 };
    static uint8_t composite[SQRT + 1];
    static int32_t primes[3500];
    int nprimes = 0;
    for (int32_t i = 2; i <= SQRT; i++) {
        if (composite[i]) continue;
        primes[nprimes++] = i;
        for (int32_t j = i * i; j <= SQRT; j += i) {
            composite[j] = 1;
        }
    }

    static int64_t rem[SEGLEN];
    static uint8_t omega[SEGLEN];  /* prime factor count mod 2 */

    int64_t sum = 0;  /* L(n), running */
    for (int64_t lo = 1; lo <= LIMIT; lo += SEGLEN) {
        int64_t hi = lo + SEGLEN;
        if (hi > LIMIT + 1) hi = LIMIT + 1;
        int64_t len = hi - lo;

        for (int64_t i = 0; i < len; i++) {
            rem[i] = lo + i;
            omega[i] = 0;
        }
        for (int p = 0; p < nprimes; p++) {
            int64_t q = primes[p];
            for (int64_t i = (q - lo % q) % q; i < len; i += q) {
                do {
                    rem[i] /= q;
                    omega[i]++;
                } while (rem[i] % q == 0);
            }
        }

        for (int64_t i = 0; i < len; i++) {
            if (rem[i] > 1) omega[i]++;      /* one prime factor > sqrt */
            sum += (omega[i] & 1) ? -1 : +1; /* lambda(n) */
            int64_t n = lo + i;
            if (sum > 0 && n >= 2) {         /* L(1) = 1 is trivial */
                printf("COUNTEREXAMPLE: L(%lld) = %lld > 0\n",
                       (long long)n, (long long)sum);
                return 0;
            }
        }
        if (lo / SEGLEN % 128 == 0) {
            fprintf(stderr, "n = %lld, L = %lld\r",
                    (long long)(hi - 1), (long long)sum);
        }
    }
    printf("no counterexample below %lld\n", (long long)LIMIT);
    return 0;
}
