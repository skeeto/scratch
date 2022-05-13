// Two Candles, One Cake with the Monte Carlo Method
//   $ cc -O3 -fopenmp -o cake cake.c -lm
//   $ cl /Ox /openmp cake.c
// Ref: https://www.youtube.com/watch?v=l5gUrDg01cQ
// This is free and unencumbered software released into the public domain.
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define N   (1L << 25)
#define PI  3.141592653589793

static uint64_t
hash64(uint64_t x)
{
    x += 1111111111111111111U; x ^= x >> 32;
    x *= 1111111111111111111U; x ^= x >> 32;
    x *= 1111111111111111111U; x ^= x >> 32;
    return x;
}

static double
rand_uniform(uint64_t s)
{
    return hash64(s) * (1 / 1.8446744073709552e19);
}

static double
rand_angle(uint64_t s)
{
    return hash64(s) * (2*PI / 1.8446744073709552e19);
}

struct v2 { double x, y; };

static struct v2
v2_rand_in_circle(uint64_t s)
{
    struct v2 v;
    do {
        v.x = rand_uniform(s++)*2 - 1;
        v.y = rand_uniform(s++)*2 - 1;
    } while (v.x*v.x + v.y*v.y > 1);
    return v;
}

static struct v2
v2_rand_on_circle(uint64_t s)
{
    double a = rand_angle(s);
    struct v2 v = {cos(a), sin(a)};
    return v;
}

static struct v2
v2_rand_radial(uint64_t s)
{
    double a = rand_angle(s+0);
    double r = rand_uniform(s+1);
    struct v2 v = {cos(a)*r, sin(a)*r};
    return v;
}

// Compute on which side of the line through a and b lies c (+1 or -1).
static int
side(struct v2 a, struct v2 b, struct v2 c)
{
    double r = (b.x - a.x)*(c.y - a.y) - (b.y - a.y)*(c.x - a.x);
    return r > 0 ? +1 : -1;
}

int main(void)
{
    long i, c;
    uint64_t t = hash64(time(0));
    uint64_t s[] = {hash64(t+1), hash64(t+2), hash64(t+3), hash64(t+4)};

    c = 0;
    #pragma omp parallel for reduction(+:c)
    for (i = 0; i < N; i++) {
        struct v2 c0 = v2_rand_in_circle(i^s[0]);
        struct v2 c1 = v2_rand_in_circle(i^s[1]);
        struct v2 e0 = v2_rand_on_circle(i^s[2]);
        struct v2 e1 = v2_rand_on_circle(i^s[3]);
        c += side(e0, e1, c0) != side(e0, e1, c1);
    }
    printf("%-24s%.17g\n", "random end points", 100.0*c/N);

    c = 0;
    #pragma omp parallel for reduction(+:c)
    for (i = 0; i < N; i++) {
        struct v2 c0 = v2_rand_in_circle(i^s[0]);
        struct v2 c1 = v2_rand_in_circle(i^s[1]);
        struct v2 e0 = v2_rand_in_circle(i^s[2]);
        struct v2 e1 = {e0.x+e0.y, e0.y-e0.x};
        c += side(e0, e1, c0) != side(e0, e1, c1);
    }
    printf("%-24s%.17g\n", "random mid point", 100.0*c/N);

    c = 0;
    #pragma omp parallel for reduction(+:c)
    for (i = 0; i < N; i++) {
        struct v2 c0 = v2_rand_in_circle(i^s[0]);
        struct v2 c1 = v2_rand_in_circle(i^s[1]);
        struct v2 e0 = v2_rand_radial(i^s[2]);
        struct v2 e1 = {e0.x+e0.y, e0.y-e0.x};
        c += side(e0, e1, c0) != side(e0, e1, c1);
    }
    printf("%-24s%.17g\n", "random radial point", 100.0*c/N);

    c = 0;
    #pragma omp parallel for reduction(+:c)
    for (i = 0; i < N; i++) {
        struct v2 c0 = v2_rand_in_circle(i^s[0]);
        struct v2 c1 = v2_rand_in_circle(i^s[1]);
        struct v2 e0 = v2_rand_in_circle(i^s[2]);
        double a = rand_angle(i^s[3]);
        struct v2 e1 = {e0.x+cos(a), e0.y+sin(a)};
        c += side(e0, e1, c0) != side(e0, e1, c1);
    }
    printf("%-24s%.17g\n", "random point+angle", 100.0*c/N);
}
