/* Prime gaps histogram animation
 *   $ cc -Ofast -o primegaps primegaps.c -lm
 *   $ ./primegaps | mpv --fps=60 --no-correct-pts -
 *   $ ./primegaps | x264 --fps=60 -o primegaps.mp4 /dev/stdin
 * Ref: https://www.youtube.com/watch?v=SMsTXQYgbiQ
 * This is free and unencumbered software released into the public domain.
 */
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIDTH    1200
#define HEIGHT   800
#define COLOR    0x7f7fff
#define NBINS    150
#define BINMAX   17
#define MAXPRIME 3121238909  // 150 millionth prime

#define LLONG_BIT (sizeof(unsigned long long) * CHAR_BIT)
#define GET(a, i) (a[(i) / LLONG_BIT] >> ((i) % LLONG_BIT) & 1ULL)
#define SET(a, i) (a[(i) / LLONG_BIT] |= 1ULL << ((i) % LLONG_BIT))

struct primesieve {
    long long n;
    long long max;
    long long sieve[];
};

static struct primesieve *
primesieve_create(long long max)
{
    struct primesieve *ps;
    size_t size = (max + LLONG_BIT - 1) / LLONG_BIT * sizeof(ps->sieve[0]);
    ps = calloc(1, sizeof(*ps) + size);
    if (ps) {
        ps->n = 0;
        ps->max = max;
    }
    return ps;
}

static long long
primesieve_next(struct primesieve *ps)
{
    if (!ps->n++)
        return 2;
    for (; ps->n * 2 - 1 < ps->max; ps->n++) {
        long long x = ps->n * 2 - 1;
        if (!GET(ps->sieve, x / 2)) {
            for (long long i = x * 3; i < ps->max; i += x * 2)
                SET(ps->sieve, i / 2);
            return x;
        }
    }
    return 0;
}

int
main(void)
{
#ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000); /* stdout to binary mode. */
#endif

    static long bins[NBINS];
    struct primesieve *ps = primesieve_create(MAXPRIME + 1);
    long long last = primesieve_next(ps);
    last = primesieve_next(ps);
    long long lastskip = 0;
    long long skip = 0;

    for (long long n = 3; ; n++) {
        long long next = primesieve_next(ps);
        if (!next) break;

        long long gap = (next - last)/2 - 1;
        if (gap < NBINS) {
            bins[gap]++;
        }
        last = next;

        /* render at this prime? */
        if (last < MAXPRIME && skip--) continue;
        fprintf(stderr, "%lld %llu\n", n, last);
        lastskip += pow(log(n), 2.8);
        skip = lastskip;

        /* render a semilog plot of the bins */
        static unsigned char ppm[HEIGHT][WIDTH][3];
        memset(ppm, 0, sizeof(ppm));
        for (int y = 0; y < HEIGHT; y++) {
            double iy = HEIGHT - y - 1;
            for (int x = 0; x < WIDTH; x++) {
                double v = log(bins[x/(WIDTH/NBINS)]);
                if (v > iy/(HEIGHT/BINMAX)) {
                    ppm[y][x][0] = 0xff & COLOR >> 16;
                    ppm[y][x][1] = 0xff & COLOR >>  8;
                    ppm[y][x][2] = 0xff & COLOR >>  0;
                }
            }
        }
        for (int i = 0; i < (last == MAXPRIME ? 60*3 : 1); i++) {
            printf("P6\n%d %d\n255\n", WIDTH, HEIGHT);
            if (!fwrite(ppm, sizeof(ppm), 1, stdout)) return 1;
        }
    }

    free(ps);
}
