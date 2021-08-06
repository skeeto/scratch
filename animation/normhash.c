/* Normal distribution via hash (animation)
 * $ cc -Ofast -o normhash normhash.c -lm
 * $ ./normhash | mpv --no-correct-pts --fps=60 -
 * $ ./normhash | x264 --fps=60 -o normhash.mp4 /dev/stdin
 * This is free and unencumbered software released into the public domain.
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define W 1920
#define H 1080
#define S 1024
#define D 7

static uint64_t
hash(int x, int y)
{
    /* SplitMix64 */
    uint64_t h = (uint64_t)y << 32 | (uint32_t)x;
    h += 0x9e3779b97f4a7c15; h ^= h >> 30;
    h *= 0xbf58476d1ce4e5b9; h ^= h >> 27;
    h *= 0x94d049bb133111eb; h ^= h >> 31;
    return h;
}

static void
norm(float *a, float *b)
{
    /* Box-Muller */
    float r = sqrtf(-2 * logf(*a));
    float s = 2 * 3.1415927f * *b;
    *a = r * cosf(s);
    *b = r * sinf(s);
}

static void
lerp(int *x, int *y, float t)
{
    uint64_t h = hash(*x, *y);
    float fx = (h & 0xffffffff) / (float)0x100000000;
    float fy = (h >> 32)        / (float)0x100000000;
    norm(&fx, &fy);
    fx = fx*(S/6) + W/2;
    fy = fy*(S/6) + H/2;
    *x = *x*(1 - t) + t*fx + 0.5f;
    *y = *y*(1 - t) + t*fy + 0.5f;
}

static float
smoothstep(float v)
{
    return 3*v*v - 2*v*v*v;
}

static float
clamp(float min, float max, float v)
{
    return v < min ? min : v > max ? max : v;
}

static unsigned char buf[H][W][3];

static void
point(int x, int y)
{
    if (x >= 0 && x < W && y >= 0 && y < H) {
        buf[y][x][0] = 255;
        buf[y][x][1] = 255;
        buf[y][x][2] = 255;
    }
}

static void
clear(void)
{
    memset(buf, 0, sizeof(buf));
}

static int
dump(void)
{
    printf("P6\n%d %d\n255\n", W, H);
    fwrite(buf, sizeof(buf), 1, stdout);
    return !ferror(stdout);
}

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    for (int i = -60; i < D*60 + 2*60; i++) {
        clear();
        for (int y = 0; y < S; y += 4) {
            for (int x = 0; x < S; x += 4) {
                int px = x + (W - S)/2, py = y + (H - S)/2;
                float t = clamp(0, 1, i / (D*60.0f));
                lerp(&px, &py, smoothstep(t));
                point(px, py);
            }
        }
        if (!dump()) return 1;
    }
}
