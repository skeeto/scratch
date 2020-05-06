/* 3D random walker animation
 * $ cc -Ofast -o walk3d walk3d.c -lm
 * $ ./walk3d | mpv --no-correct-pts --fps=60 -
 * $ ./walk3d | x264 --fps 60 --frames 3600 -o walk3d.mp4 /dev/stdin
 * https://redd.it/geka1q
 * https://nullprogram.com/video/?v=walk3d
 * This is free and unencumbered software released into the public domain.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define N      32
#define W      1024
#define H      1024
#define SCALE  25.0f
#define MAX    150
#define DELAY  25

#define PI 3.1415927f

static unsigned long long u32s;

static unsigned long u32(void)
{
    return (u32s = u32s*0xfc5434fdb4a9e74d + 1) >> 32 & 0xffffffff;
}

static float rnd(float min, float max)
{
    return ldexpf(u32(), -32)*(max - min) + min;
}

struct v2 { int x, y; };
struct v3 { float x, y, z; };

/* Orthographic projection of 3D point into the screen. */
static struct v2
project(struct v3 p, float scale, float az, float el)
{
    float x = p.x*cosf(az) - p.y*sinf(az);
    float y = p.x*sinf(az) + p.y*cosf(az);
    return (struct v2){
        roundf(scale*x + W/2),
        roundf(scale*(y*sinf(el) + p.z*cosf(el)) + H/2)
    };
}

static unsigned char buf[H][W][3];

static void clear(void) { memset(buf, 0, sizeof(buf)); }

static void
point(struct v2 p, long color)
{
    if (p.x >= 0 && p.x < W && p.y >= 0 && p.y < H) {
        buf[p.y][p.x][0] = color >> 16;
        buf[p.y][p.x][1] = color >>  8;
        buf[p.y][p.x][2] = color >>  0;
    }
}

static void
line(struct v2 a, struct v2 b, long color)
{
    int dx = abs(b.x - a.x);
    int dy = abs(b.y - a.y);
    int sx = b.x < a.x ? -1 : 1;
    int sy = b.y < a.y ? -1 : 1;
    if (dx > dy) {
        int d = 2 * dy - dx;
        struct v2 p = {0, a.y};
        for (p.x = a.x; p.x != b.x; p.x += sx) {
            point(p, color);
            if (d > 0) {
                p.y += sy;
                d -= 2 * dx;
            }
            d += 2 * dy;
        }
    } else {
        int d = 2 * dx - dy;
        struct v2 p = {a.x, 0};
        for (p.y = a.y; p.y != b.y; p.y += sy) {
            point(p, color);
            if (d > 0) {
                p.x += sx;
                d -= 2 * dy;
            }
            d += 2 * dx;
        }
    }
    point(b, color);
}

static void
frame(void)
{
    #define xstr(s) str(s)
    #define str(s) #s
    const char header[] = "P6\n" xstr(W) " " xstr(H) "\n255\n";
    fwrite(header, sizeof(header) - 1, 1, stdout);
    if (!fwrite(buf, sizeof(buf), 1, stdout)) exit(1);
}

static float
biasrnd(float v)
{
    float bias = 0.1f;
    float r = v + rnd(-1.0f, +1.0f);
    if (v < 0.0f) {
        r -= bias;
    } else if (v > 0.0f) {
        r += bias;
    }
    return r;
}

static void
animate(void)
{
    struct {
        long color;
        struct v3 pos[MAX];
    } points[N];

    for (int i = 0; i < N; i++) {
        points[i].color = u32()>>8 | 0x404040;
        points[i].pos[0].x = 0;
        points[i].pos[0].y = 0;
        points[i].pos[0].z = 0;
        for (int j = 1; j < MAX; j++) {
            points[i].pos[j].x = biasrnd(points[i].pos[j-1].x);
            points[i].pos[j].y = biasrnd(points[i].pos[j-1].y);
            points[i].pos[j].z = biasrnd(points[i].pos[j-1].z);
        }
    }

    float az = 0;
    float daz = rnd(+0.005f, +0.02) * (u32()&1 ? -1 : 1);
    float el = 0;
    float del = rnd(0.0f, +0.005f) * (u32()&1 ? -1 : 1);
    for (int n = 0; n < MAX*DELAY; n++) {
        clear();
        for (int i = 0; i < N; i++) {
            struct v2 p = project(points[i].pos[0], SCALE, az, el);
            for (int j = 1; j < n/DELAY; j++) {
                struct v2 c = project(points[i].pos[j], SCALE, az, el);
                line(p, c, points[i].color);
                p = c;
            }
            struct v2 c = project(points[i].pos[n/DELAY], SCALE, az, el);
            float t = n % DELAY / (float)DELAY;
            struct v2 r = {
                roundf(p.x + t*(c.x - p.x)),
                roundf(p.y + t*(c.y - p.y))
            };
            line(p, r, points[i].color);
            point((struct v2){r.x+1, r.y+0}, points[i].color);
            point((struct v2){r.x-1, r.y+0}, points[i].color);
            point((struct v2){r.x+0, r.y+1}, points[i].color);
            point((struct v2){r.x+0, r.y-1}, points[i].color);
        }
        frame();
        az = az*0.999f + daz;
        daz += rnd(-0.0001, +0.0001);
        el = el*0.999f + del;
        del += rnd(-0.0001, +0.0001);
    }
}

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000); /* Set stdin/stdout to binary mode. */
    #endif

    u32s = time(0);
    for (;;) {
        animate();
        u32s ^= clock();
    }
}
