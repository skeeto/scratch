// This is free and unencumbered software released into the public domain.
#define MT19937_IMPLEMENTATION
#include "mt19937.h"

#define MT19937_64_IMPLEMENTATION
#include "mt19937_64.h"

#include <stdio.h>
#include <string.h>

#define SEED 0xdeadbeef
static const uint32_t expect[] = {
    0x39037a7d, 0xe5052ed8, 0xc5dc5c6e, 0x6ddccbe1, 0xa13aed6c, 0x23839b39,
    0x37f0a862, 0x63e92751, 0xc0016042, 0x6c6c241d, 0x8f283c12, 0x94a7dc55,
    0x2dbdac59, 0x5ec675b1, 0xa4eb5ff7, 0xeb813ae4, 0x99114764, 0x980d276a,
    0x9d7b14d9, 0x21decbc9, 0x7699ccf0, 0xd94b143b, 0x5bb8e05a, 0xb1a748cd,
    0xf5a4d1a7, 0x4e9e983c, 0x3c2cc2f7, 0x4cfba7c9, 0x183008af, 0xd3ce2698,
    0x34b2311a, 0x80b830f2, 0x936b8400, 0x20064868, 0xd0de8b3b, 0xc6797364,
};
static const int nexpect = sizeof(expect)/sizeof(*expect);

#define SEED64 0x3243f6a8885a308d
static const uint64_t expect64[] = {
    0x26a7369ee2256e41, 0x186de3f44b532d15, 0x62500624544ebcda,
    0xe478a1a226320ab4, 0xee22d006d61f2c16, 0x185482bc8950e61e,
    0x0b23c80f8d5bfe03, 0x0af714afffb33e0c, 0xf1fe2bc6442bc212,
    0xa9b7b7222783f83b, 0x77062658d2d7157b, 0x397a77f42d70dda5,
    0xc8b53a80c049a117, 0x67e291b153b5622a, 0x5fd35eff20394f02,
    0xcb0fdecf949d2a0b, 0x7962ad34a07a6f3c, 0x1f0474c3700f422d,
    0x4d06eb84ee50437d, 0xc7029e939a097c6c, 0xf2342f5c595fbcd9,
    0xeac83e27f17ba5ef, 0x5e341371b0137e98, 0x11a3222701322d44,
    0x3e49ff6df85fec79, 0x1f4b7c3e2853d7f1, 0x4059a5fa31961b26,
    0x751cdb491e6987d4, 0x7d2b2fa3721c1c06, 0xd1dc12918a3a2f86,
};
static const int nexpect64 = sizeof(expect64)/sizeof(*expect64);

#ifdef _WIN32
#include <windows.h>
static double
now(void)
{
    LARGE_INTEGER f, t;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / f.QuadPart;
}

#else
#include <time.h>
static double
now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec/1e9;
}
#endif

static int
dump(void)
{
    #define N (1<<12)
    static uint32_t buf[N];
    struct mt19937 mt[1];
    mt19937_init(mt, 0);
    for (;;) {
        for (int i = 0; i < N; i++) {
            buf[i] = mt19937_next(mt);
        }
        if (!fwrite(buf, sizeof(buf), 1, stdout)) break;
    }
    return 0;
}

static int
dump64(void)
{
    #define N64 (1<<11)
    static uint64_t buf[N64];
    struct mt19937_64 mt64[1];
    mt19937_64_init(mt64, 0);
    for (;;) {
        for (int i = 0; i < N64; i++) {
            buf[i] = mt19937_64_next(mt64);
        }
        if (!fwrite(buf, sizeof(buf), 1, stdout)) break;
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    int fails = 0;

    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    /* Useful for piping into PractRand, BigCrush, dieharder, etc. */
    switch (argc) {
    case  0:
    case  1: break;
    case  2: if (!strcmp(argv[1], "32")) return dump();
             if (!strcmp(argv[1], "64")) return dump64();
             /* fallthrough */
    default: fprintf(stderr, "fatal: invalid arguments\n");
             return 1;
    }

    /* Test mt19937-32 */
    struct mt19937 mt[1];
    mt19937_init(mt, SEED);
    for (int i = 0; i < nexpect; i++) {
        unsigned long want = expect[i];
        unsigned long got  = mt19937_next(mt);
        if (want != got) {
            printf("FAIL: 32-%02d want %08lx, got %08lx\n", i, want, got);
            fails++;
        }
    }

    /* Test mt19937-64 */
    struct mt19937_64 mt64[1];
    mt19937_64_init(mt64, SEED64);
    for (int i = 0; i < nexpect64; i++) {
        unsigned long long want = expect64[i];
        unsigned long long got  = mt19937_64_next(mt64);
        if (want != got) {
            printf("FAIL: 64-%02d want %016llx, got %016llx\n", i, want, got);
            fails++;
        }
    }

    if (fails) {
        return 1;
    }

    /* Benchmark mt19937-32 */
    long n = 1L<<27;
    uint32_t t = 0;
    double start = now();
    for (long i = 0; i < n; i++) {
        t += mt19937_next(mt);
    }
    volatile uint32_t sink = t; (void)sink;
    double dt = now() - start;
    printf("mt19937-32: %.6f GiB/sec\n", n / 268435456.0 / dt);

    /* Benchmark mt19937-64 */
    long n64 = 1L<<28;
    uint64_t t64 = 0;
    double start64 = now();
    for (long i = 0; i < n64; i++) {
        t64 += mt19937_64_next(mt64);
    }
    volatile uint64_t sink64 = t64; (void)sink64;
    double dt64 = now() - start64;
    printf("mt19937-64: %.6f GiB/sec\n", n64 / 134217728.0 / dt64);
}
