/* Monte Carlo Method pi estimate via 128-bit integer math
 * This is free and unencumbered software released into the public domain.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define NTHREADS 8
#define REPORT   0x10000000

static uint64_t
xoshiro256ss(uint64_t s[4])
{
    uint64_t x = s[1] * 5;
    uint64_t r = ((x << 7) | (x >> 57)) * 9;
    uint64_t t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = (s[3] << 45) | (s[3] >> 19);
    return r;
}

static uint64_t
splittable64(uint64_t x)
{
    x += 0x9e3779b97f4a7c15U; x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9U; x ^= x >> 27;
    x *= 0x94d049bb133111ebU; x ^= x >> 31;
    return x;
}

static void
accum(long i)
{
    static uint64_t inside, total;
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&lock);
        inside += i;
        total += REPORT;
        printf("%-20.17g %16.9f %16.9f\n",
               inside*4.0/total, inside/1e9, total/1e9);
        fflush(stdout);
    pthread_mutex_unlock(&lock);
}

static void *
worker(void *n)
{
    uint64_t seed = splittable64(time(0)) + (uintptr_t)n*8;
    uint64_t s0[] = {
        splittable64(seed+0), splittable64(seed+1),
        splittable64(seed+2), splittable64(seed+3),
    };
    uint64_t s1[] = {
        splittable64(seed+4), splittable64(seed+5),
        splittable64(seed+6), splittable64(seed+7),
    };
    for (;;) {
        long inside = 0;
        for (long i = 0; i < REPORT; i++) {
            unsigned __int128 x = xoshiro256ss(s0) >> 1;
            unsigned __int128 y = xoshiro256ss(s1) >> 1;
            unsigned __int128 r = (1ULL<<63) - 1;
            inside += x*x + y*y <= r*r;
        }
        accum(inside);
    }
    return 0;
}

int
main(void)
{
    for (int i = 1; i < NTHREADS; i++) {
        pthread_t thr;
        pthread_create(&thr, 0, worker, (void *)(uintptr_t)i);
    }
    worker((void *)(uintptr_t)NTHREADS);
}
