/* Sort lines independently and animate it
 *   $ cc -O3 -DN=720 -o colorsort colorsort.c
 *   $ ./colorsort | mpv --no-correct-pts --fps=30 -
 * https://nullprogram.com/video/?v=colors-odd-even
 * https://redd.it/73oz1x
 * This is free and unencumbered software released into the public domain.
 */
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef N
#  define N 360
#endif

static uint32_t
pcg32(uint64_t s[1])
{
    uint64_t m = 0x9b60933458e17d7d;
    uint64_t a = 0xd737232eeccdf7ed;
    *s = *s * m + a;
    int shift = 29 - (*s >> 61);
    return *s >> shift;
}

static int
mod(int a, int b)
{
    return (a % b + b) % b;
}

static void
print_pixel(int v)
{
    int h = mod(v, N) / (N / 6);
    int f = mod(v, N) % (N / 6);
    int t = 255 * f / (N / 6);
    int q = 255 - t;
    switch (h) {
        case 0:
            putchar(0xff);
            putchar(t);
            putchar(0);
            break;
        case 1:
            putchar(q);
            putchar(0xff);
            putchar(0);
            break;
        case 2:
            putchar(0);
            putchar(0xff);
            putchar(t);
            break;
        case 3:
            putchar(0);
            putchar(q);
            putchar(0xff);
            break;
        case 4:
            putchar(t);
            putchar(0);
            putchar(0xff);
            break;
        case 5:
            putchar(0xff);
            putchar(0);
            putchar(q);
            break;
    }
}

static void
dump(int image[N][N])
{
    printf("P6\n%d %d\n255\n", N, N);
    for (int y = 0; y < N; y++)
        for (int x = 0; x < N; x++)
            print_pixel(image[y][x]);
    if (fflush(stdout)) exit(1);
}

static void
image_init(int image[N][N])
{
    for (int y = 0; y < N; y++)
        for (int x = 0; x < N; x++)
            image[y][x] = x;
}

static void
image_shuffle(int image[N][N], uint64_t *s)
{
    for (int y = 0; y < N; y++) {
        for (int x = N - 1; x > 1; x--) {
            int i = pcg32(s) % (x + 1);
            int tmp = image[y][x];
            image[y][x] = image[y][i];
            image[y][i] = tmp;
        }
    }
}

static long
image_sort_step(int image[N][N])
{
    /* Odd-even sort */
    long c = 0;
    for (int y = 0; y < N; y++) {
        for(int x = 1; x < N - 1; x += 2) {
            if (image[y][x] > image[y][x + 1]) {
                int tmp = image[y][x];
                image[y][x] = image[y][x + 1];
                image[y][x + 1] = tmp;
                c++;
            }
        }
        for (int x = 0; x < N - 1; x += 2) {
            if (image[y][x] > image[y][x + 1]) {
                int tmp = image[y][x];
                image[y][x] = image[y][x + 1];
                image[y][x + 1] = tmp;
                c++;
            }
        }
    }
    return c;
}

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    static int image[N][N];
    uint64_t s[] = {0xf34813d8cc836d98};
    *s ^= time(0);
    image_init(image);
    image_shuffle(image, s);
    do
        dump(image);
    while (image_sort_step(image));
    dump(image);
}
