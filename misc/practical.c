// Practical number test predicate (with tests)
//   $ cc -fopenmp -O3 -o practical practical.c
//   $ cl /openmp /O2 practical.c
// Ref: https://old.reddit.com/r/dailyprogrammer/comments/13m4bz1
// Ref: https://www.youtube.com/watch?v=IlZOLwf87gM
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <stdint.h>

#define K 8  // primality test iterations

static uint64_t rand64(void)
{
    static uint64_t x = 1;
    uint64_t r = x = x*0x3243f6a8885a308d + 1;
    return r ^ r>>32;
}

static uint64_t modmult(uint64_t b, uint64_t e, uint64_t m)
{
    uint64_t sum = 0;
    if (b == 0 || e < m / b)
        return (b * e) % m;
    while (e > 0) {
        if (e % 2 == 1)
            sum = (sum + b) % m;
        b = (2 * b) % m;
        e /= 2;
    }
    return sum;
}

static uint64_t modexp(uint64_t b, uint64_t e, uint64_t m)
{
    uint64_t product = 1;
    uint64_t pseq = b % m;
    while (e > 0) {
        if (e % 2 == 1)
            product = modmult(product, pseq, m);
        pseq = modmult(pseq, pseq, m);
        e /= 2;
    }
    return product;
}

static int iscomposite(uint64_t n, uint64_t d, int r)
{
    uint64_t a = 2 + rand64() % (n - 3);
    if (modexp(a, d, n) == 1)
        return 0;
    for (int i = 0; i < r; i++)
        if (modexp(a, (UINT64_C(1) << i) * d, n) == n - 1)
            return 0;
    return 1;
}

static int isprime(uint64_t n)
{
    int r = 0;
    uint64_t d = n - 1;
    for (; d % 2 == 0; r++)
        d /= 2;
    for (int i = 0; i < K; i++)
        if (iscomposite(n, d, r))
            return 0;
    return 1;
}

struct reduced {
    uint64_t remainder;
    uint64_t product;
    uint64_t divsum;
};

static struct reduced divide_out(uint64_t num, uint64_t den)
{
    struct reduced r = {num, 1, 1};
    for (uint64_t fig = 1; r.remainder%den == 0;) {
        r.product *= den;
        r.remainder /= den;
        r.divsum += fig *= den;
    }
    return r;
}

static int ispractical(uint64_t x)
{
    uint64_t product = 1;
    uint64_t divsum = 1;
    struct reduced r = divide_out(x, 2);
    x = r.remainder;
    product *= r.product;
    divsum *= r.divsum;
    if (x>1 && divsum==1) {
        return 0;
    }
    if (x>1 && isprime(x)) {
        return x-1 <= divsum;
    }

    for (uint64_t n = 3; n <= x; n += 2) {
        if (!(x % n)) {
            if (n-1 > divsum) {
                return 0;
            }
            struct reduced r = divide_out(x, n);
            x = r.remainder;
            product *= r.product;
            divsum *= r.divsum;
            if (x>1 && isprime(x)) {
                return x-1 <= divsum;
            }
        }
    }
    return 1;
}

int main(void)
{
    int i;
    uint64_t sum = 0;
    uint64_t base = 10000000000000000000U;  // 10**19
    #pragma omp parallel for schedule(dynamic) reduction(+:sum)
    for (i = 1; i <= 10000; i++) {
        if (ispractical(base + i)) {
            sum += i;
        }
    }
    printf("%llu\n", (unsigned long long)sum);
}
