/* Bitset Sieve of Eratosthenes
 * This is free and unencumbered software released into the public domain.
 */
#include <limits.h>
#include <stdlib.h>

#define LLONG_BIT (sizeof(unsigned long long) * CHAR_BIT)
#define GET(a, i) (a[(i) / LLONG_BIT] >> ((i) % LLONG_BIT) & 1ULL)
#define SET(a, i) (a[(i) / LLONG_BIT] |= 1ULL << ((i) % LLONG_BIT))

struct primesieve {
    unsigned long long n;
    unsigned long long max;
    unsigned long long sieve[];
};

static struct primesieve *
primesieve_create(unsigned long long max)
{
    struct primesieve *ps;
    size_t size = (max / 2 + LLONG_BIT - 1) / LLONG_BIT * sizeof(ps->sieve[0]);
    ps = calloc(1, sizeof(*ps) + size);
    if (ps) {
        ps->n = 0;
        ps->max = max;
    }
    return ps;
}

static unsigned long long
primesieve_next(struct primesieve *ps)
{
    if (!ps->n++)
        return 2;
    for (; ps->n * 2 - 1 < ps->max; ps->n++) {
        unsigned long long x = ps->n * 2 - 1;
        if (!GET(ps->sieve, x / 2)) {
            for (unsigned long long i = x * 3; i < ps->max; i += x * 2)
                SET(ps->sieve, i / 2);
            return x;
        }
    }
    return 0;
}
