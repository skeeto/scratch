// Luhn algorithm credit card check using 64-bit SWAR
// This is free and unencumbered software released into the public domain.

// Is this 16-digit credit card number valid?
static int
luhn(const char *s)
{
    // Load two 64-bit little endian integers, operate as SWAR
    unsigned char *p = (unsigned char *)s;
    unsigned long long hi =
        (unsigned long long)p[ 0] <<  0 | (unsigned long long)p[ 1] <<  8 |
        (unsigned long long)p[ 2] << 16 | (unsigned long long)p[ 3] << 24 |
        (unsigned long long)p[ 4] << 32 | (unsigned long long)p[ 5] << 40 |
        (unsigned long long)p[ 6] << 48 | (unsigned long long)p[ 7] << 56;
    unsigned long long lo =
        (unsigned long long)p[ 8] <<  0 | (unsigned long long)p[ 9] <<  8 |
        (unsigned long long)p[10] << 16 | (unsigned long long)p[11] << 24 |
        (unsigned long long)p[12] << 32 | (unsigned long long)p[13] << 40 |
        (unsigned long long)p[14] << 48 | (unsigned long long)p[15] << 56;
    hi -= 0x3030303030303030;  // decode ASCII characters
    lo -= 0x3030303030303030;
    hi += hi & 0x00ff00ff00ff00ff;  // double every other digit
    lo += lo & 0x00ff00ff00ff00ff;
    hi += (hi + 0x0006000600060006)>>4 & 0x0001000100010001;  // add tens
    lo += (lo + 0x0006000600060006)>>4 & 0x0001000100010001;
    hi += hi >> 32; lo += lo >> 32;  // channel-wise sum
    hi += hi >> 16; lo += lo >> 16;
    hi += hi >>  8; lo += lo >>  8;
    return !(((hi&255) + (lo&255)) % 10);  // sum SWAR results and check
}

#if TEST
#include <assert.h>
#include <stdio.h>

static int
luhn_simple(const char *s)
{
    int n = 0;
    for (int i = 0; i < 16; i++) {
        int v = (s[i] - '0') << !(i&1);
        n += v;
        n += v >= 10;
    }
    return !(n%10);
}

int
main(void)
{
    assert(luhn("5555555555554444"));
    assert(luhn("5105105105105100"));
    assert(luhn("4111111111111111"));
    assert(luhn("4012888888881881"));

    #pragma omp parallel for
    for (long i = 0; i < 1L<<26; i++) {
        unsigned long long v = i;
        v += 1111111111111111111U; v ^= v >> 32;
        v *= 1111111111111111111U; v ^= v >> 32;
        v *= 1111111111111111111U; v ^= v >> 32;
        char card[16] = {
            '0' + v / 1 % 10,               '0' + v / 10 % 10,
            '0' + v / 100 % 10,             '0' + v / 1000 % 10,
            '0' + v / 10000 % 10,           '0' + v / 100000 % 10,
            '0' + v / 1000000 % 10,         '0' + v / 10000000 % 10,
            '0' + v / 100000000 % 10,       '0' + v / 1000000000 % 10,
            '0' + v / 10000000000 % 10,     '0' + v / 100000000000 % 10,
            '0' + v / 1000000000000 % 10,   '0' + v / 10000000000000 % 10,
            '0' + v / 100000000000000 % 10, '0' + v / 1000000000000000 % 10
        };
        assert(luhn(card) == luhn_simple(card));
    }
}

#elif BENCH
// This benchmark clocks it about 3x faster than luhn_simple on my machine.
#include <stdio.h>
#include <stdint.h>

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

int
main(void)
{
    static const char cards[][16] = {
        "5555555555554444", "5105105105105100",
        "4111111111111111", "4012888888881881",
    };

    long n = 1L << 28;
    double start = now();
    long r = 0;
    for (long i = 0; i < n; i++) {
        uint32_t n = i;
        r += luhn(cards[(n*0x1c5bf891U)>>30]);  // random draw
    }
    volatile long sink = r; (void)sink;
    printf("%.3f M-ops/s\n", n / 1e6 / (now() - start));
}
#endif
