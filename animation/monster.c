// Monster tentacles
//   $ cc -Ofast -o monster monster.c -lm
//   $ ./monster | mpv --no-correct-pts --fps=60 --fs -
//   $ ./monster | x264 --frames=430 --fps=60 -o monster.mp4 /dev/stdin
// Ref: https://old.reddit.com/r/proceduralgeneration/comments/vvgyut
// This is free and unencumbered software released into the public domain.
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define WIDTH  1920
#define HEIGHT 1080
#define FPS    60
#define STEPS  250
#define NARMS  15
#define CSTART 0x500050L
#define CSTOP  0xffc8ffL
#define BG     0x10
#define FUZZ   1.5f
#define SPEED  3.5f
#define START  50.0f
#define STOP   3.0f
#define CURVE  (PI/12)
#define PI     3.141592654f

static float
clamp(float x, float lower, float upper)
{
    if (x < lower) {
        return lower;
    } else if (x > upper) {
        return upper;
    }
    return x;
}

static float
smoothstep(float lower, float upper, float x)
{
    x = clamp((x - lower) / (upper - lower), 0.0f, 1.0f);
    return x * x * (3.0f - 2.0f*x);
}

static long
lerp(long c0, long c1, float a)
{
    unsigned char r0 = c0>>16, g0 = c0>>8, b0 = c0>>0;
    unsigned char r1 = c1>>16, g1 = c1>>8, b1 = c1>>1;
    float k = 1 - a;
    return (long)(a*r0 + k*r1) << 16 |
           (long)(a*g0 + k*g1) <<  8 |
           (long)(a*b0 + k*b1) <<  0;
}

static unsigned char ppm[HEIGHT][WIDTH][3];

static void
put(int x, int y, long c, float a)
{
    if (x >= 0 && x < WIDTH && y >= 0 && y < HEIGHT) {
        float k = 1 - a;
        ppm[y][x][0] = k*ppm[y][x][0] + a*(c >> 16       );
        ppm[y][x][1] = k*ppm[y][x][1] + a*(c >>  8 & 0xff);
        ppm[y][x][2] = k*ppm[y][x][2] + a*(c       & 0xff);
    }
}

static void
clear(void)
{
    memset(ppm, BG, sizeof(ppm));
}

static void
circle(float x, float y, float r, long c)
{
    int x0 = x-r-1, x1 = x+r+1;
    int y0 = y-r-1, y1 = y+r+1;
    float r0 = clamp(r - FUZZ, 0, r);
    for (int py = y0; py <= y1; py++) {
        float dy = py - y;
        for (int px = x0; px <= x1; px++) {
            float dx = px - x;
            float d2 = dx*dx + dy*dy;
            put(px, py, c, 1-smoothstep(r0*r0, r*r, d2));
        }
    }
}

static void
frame(void)
{
    #define STR(x) #x
    #define XSTR(x) STR(x)
    static const char hdr[] = "P6\n"XSTR(WIDTH)" "XSTR(HEIGHT)"\n255\n";
    fwrite(hdr, sizeof(hdr)-1, 1, stdout);
    fwrite(ppm, sizeof(ppm), 1, stdout);
}

static float
uniform(unsigned long long *s)
{
    *s = *s*0x3243f6a8885a308dULL + 1;
    return (*s>>32 & 0xffffffff) / 4294967296.0f;
}

int
main(void)
{
    struct { float x, y, a; } arms[NARMS];
    unsigned long long rng[] = {time(0)};

    #if _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    do {
        clear();

        *rng += clock();
        for (int i = 0; i < NARMS; i++) {
            arms[i].x = WIDTH/2;
            arms[i].y = HEIGHT/2;
            arms[i].a = uniform(rng)*PI*2;
        }

        for (int n = 0; n < STEPS; n++) {
            float a = 1 - (float)n / STEPS;
            float speed = sqrtf(a) * SPEED;
            float size = STOP + a*(START - STOP);
            long c = lerp(CSTART, CSTOP, a);
            for (int i = 0; i < NARMS; i++) {
                arms[i].a += uniform(rng)*2*CURVE - CURVE;
                arms[i].x += speed * cosf(arms[i].a);
                arms[i].y += speed * sinf(arms[i].a);
                circle(arms[i].x, arms[i].y, size, c);
            }
            frame();
        }

        for (int i = 0; i < FPS*3; i++) {
            frame();
        }
    } while (!ferror(stdout));
}
