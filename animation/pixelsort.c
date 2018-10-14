/* N-pixel sorting
 * For each pixel P from left to right, top to bottom, select N random
 * unvisited pixels and swap P with the one most similar pixel to the
 * surroundings of P.
 *   $ cc -O3 -o pixelsort pixelsort.c
 *   $ ./pixelsort <picture.ppm | mpv --no-correct-pts --fps=60 -
 * Ref: https://redd.it/9o1plu
 * Ref: https://nullprogram.com/video/?v=pixelsort
 * This is free and unencumbered software released into the public domain.
 */
#include <time.h>
#include <float.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

struct ppm {
    long width;
    long height;
    unsigned char data[];
};

static struct ppm *
ppm_create(long width, long height)
{
    struct ppm *m = malloc(sizeof(*m) + width * height * 3);
    m->width = width;
    m->height = height;
    return m;
}

static void
ppm_write(struct ppm *m, FILE *f)
{
    printf("P6\n%ld %ld\n255\n", m->width, m->height);
    if (!fwrite(m->data, m->width * m->height, 3, f)) exit(1);
}

static struct ppm *
ppm_read(FILE *f)
{
    struct ppm *m;
    long width, height;
    if (scanf("P6 %ld%ld%*d%*c", &width, &height) < 2)
        return 0;
    m = ppm_create(width, height);
    fread(m->data, width * height, 3, f);
    return m;
}

static uint32_t
xorshift32(uint32_t s[1])
{
    uint32_t x = s[0];
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s[0] = x;
    return x;
}

static uint32_t
hash32(uint32_t x)
{
    x ^= x >> 17;
    x *= UINT32_C(0xed5ad4bb);
    x ^= x >> 11;
    x *= UINT32_C(0xac4c1b51);
    x ^= x >> 15;
    x *= UINT32_C(0x31848bab);
    x ^= x >> 14;
    return x;
}

static double
score(const struct ppm *m, long p0, long p1)
{
    static const int visit[] = {-1, -1, -1, +0, -1, +1, +0, -1};
    static const int nvisit = sizeof(visit) / sizeof(*visit) / 2;
    int count = 0;
    long score = 0;
    long x0 = p0 % m->width;
    long y0 = p0 / m->width;
    const unsigned char *rgb1 = m->data + p1 * 3;
    for (int i = 0; i < nvisit; i++) {
        long x = x0 + visit[i * 2 + 0];
        long y = y0 + visit[i * 2 + 1];
        if (x >= 0 && y >= 0 && x < m->width && y < m->height) {
            const unsigned char *rgb = m->data + y * m->width * 3 + x * 3;
            score += abs(rgb[0] - rgb1[0]);
            score += abs(rgb[1] - rgb1[1]);
            score += abs(rgb[2] - rgb1[2]);
            count++;
        }
    }
    return count ? score / (double)count : DBL_MAX;
}

static void
swap(struct ppm *m, long p0, long p1)
{
    unsigned char *rgb0 = m->data + p0 * 3;
    unsigned char *rgb1 = m->data + p1 * 3;
    for (int i = 0; i < 3; i++) {
        int tmp = rgb0[i];
        rgb0[i] = rgb1[i];
        rgb1[i] = tmp;
    }
}

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    int n = 1024;
    uint32_t rng[1] = {0x2b461c85};
    struct ppm *m = ppm_read(stdin);

    *rng ^= hash32(time(0));
    for (long p = 0; p < m->width * m->height - 1; p++) {
        long best = -1;
        double best_score = DBL_MAX;
        for (int i = 0; i < n; i++) {
            long try = p + xorshift32(rng) % (m->height * m->width - p);
            double value = score(m, p, try);
            if (value < best_score) {
                best = try;
                best_score = value;
            }
        }
        if (best != -1)
            swap(m, p, best);

        /* Write one frame per line */
        if (p % m->width == 0)
            ppm_write(m, stdout);
    }

    ppm_write(m, stdout);
}
