// Endless 2D Galton board animation
//
// Usage:
//   $ cc -Ofast -mrecip -o galton galton.c -lm
//   $ ./galton | mpv --no-correct-pts --fps=60 --fs -
//   $ ./galton | x264 --frames=1800 --fps=60 -o galton.mp4 /dev/stdin
//
// This is free and unencumbered software released into the public domain.
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// Configuration
#define W      1920         // video width
#define H      1080         // video height
#define S      200.0f       // display scale (m/pixel)
#define NBALLS 312          // number of falling balls to simulate
#define NHIST  96           // number of histogram bins
#define SKIP   1024         // simulation initialization time
#define PW     50           // pegs wide count
#define PH     36           // pegs tall count (must be even)
#define MINR   0.03f        // minimum ball radious (m)
#define MAXR   0.06f        // maximum ball radious (m)
#define PEGR   0.02f        // peg radious (m)
#define G      9.8f         // gravity (m/s)
#define E      0.80f        // elasticity
#define DT     (1.0f / 60)  // time step (1/FPS)

#define PI 3.1415927f
#define NPEGS  (PH/2*(2*PW - 1))
#define COUNTOF(a) (sizeof(a) / sizeof(0[a]))

static float
clamp(float x, float lower, float upper)
{
    if (x < lower) {
        return lower;
    }
    if (x > upper) {
        return upper;
    }
    return x;
}

static float
smoothstep(float lower, float upper, float x)
{
    x = clamp((x - lower) / (upper - lower), 0.0f, 1.0f);
    return x * x * (3.0f - 2.0f * x);
}

static void
rgb_split(int32_t c, float *r, float *g, float *b)
{
    *r = ((c >> 16) / 255.0f);
    *g = (((c >> 8) & 0xff) / 255.0f);
    *b = ((c & 0xff) / 255.0f);
}

static int32_t
rgb_join(float r, float g, float b)
{
    int32_t ir = roundf(r * 255.0f);
    int32_t ig = roundf(g * 255.0f);
    int32_t ib = roundf(b * 255.0f);
    return (ir << 16) | (ig << 8) | ib;
}

// Pseudo-random number generation

static uint64_t
hash64(uint64_t x)
{
    x += 0x2b7e151628aed2a6U; x ^= x >> 32;
    x *= 0x3243f6a8885a308dU; x ^= x >> 32;
    x *= 0xb17217f7d1cf79abU; x ^= x >> 32;
    return x;
}

static uint64_t
rng64(uint64_t s[1])
{
    uint64_t r = (*s += 1111111111111111111U);
    r ^= r >> 33;  r *= 1111111111111111111U;
    r ^= r >> 33;  r *= 1111111111111111111U;
    r ^= r >> 33;
    return r;
}

static float
rng(uint64_t s[1], float min, float max)
{
    float u = (rng64(s)>>40) / 16777216.0f;
    return min + u*(max - min);
}

// 2D vector library

struct v2 { float x, y; };

static float
v2_norm(struct v2 v)
{
    return sqrtf(v.x*v.x + v.y*v.y);
}

static struct v2
v2_normalize(struct v2 v)
{
    float a = v2_norm(v);
    return (struct v2){v.x/a, v.y/a};
}

static struct v2
v2_add(struct v2 a, struct v2 b)
{
    return (struct v2){a.x + b.x, a.y + b.y};
}

static struct v2
v2_sub(struct v2 a, struct v2 b)
{
    return (struct v2){a.x - b.x, a.y - b.y};
}

static struct v2
v2_scale(struct v2 v, float s)
{
    return (struct v2){s*v.x, s*v.y};
}

static float
v2_dist2(struct v2 a, struct v2 b)
{
    struct v2 d = v2_sub(a, b);
    return d.x*d.x + d.y*d.y;
}

static float
v2_dot(struct v2 a, struct v2 b)
{
    return a.x*b.x + a.y*b.y;
}

// PPM rendering library

static unsigned char ppm[H][W][3];

static int
ppm_write(void)
{
    #define STR(s) #s
    #define XSTR(s) STR(s)
    static const char header[] = "P6\n" XSTR(W) " " XSTR(H) "\n255\n";
    return fwrite(header, sizeof(header)-1, 1, stdout) &&
           fwrite(ppm, sizeof(ppm), 1, stdout);
}

static void
ppm_clear(void)
{
    memset(ppm, 0, sizeof(ppm));
}

static void
ppm_set(int x, int y, int32_t color)
{
    if (x >= 0 && x < W && y >= 0 && y < H) {
        ppm[y][x][0] = color >> 16;
        ppm[y][x][1] = color >>  8;
        ppm[y][x][2] = color >>  0;
    }
}

static int32_t
ppm_get(int x, int y)
{
    if (x >= 0 && x < W && y >= 0 && y < H) {
        int32_t r = ppm[y][x][0];
        int32_t g = ppm[y][x][1];
        int32_t b = ppm[y][x][2];
        return (r << 16) | (g << 8) | b;
    }
    return 0;
}

static void
ppm_circle(float x, float y, float r0, float r1, int32_t color)
{
    float fr, fg, fb;
    rgb_split(color, &fr, &fg, &fb);

    int miny = floorf(y - r1 - 1), maxy = ceilf(y + r1 + 1);
    int minx = floorf(x - r1 - 1), maxx = ceilf(x + r1 + 1);

    for (int py = miny; py <= maxy; py++) {
        float dy = py - y;
        for (int px = minx; px <= maxx; px++) {
            float dx = px - x;
            float d = sqrtf(dy*dy + dx*dx);
            float a = smoothstep(r1, r0, d);

            int32_t bgc = ppm_get(px, py);
            float br, bg, bb;
            rgb_split(bgc, &br, &bg, &bb);

            float r = a*fr + (1 - a)*br;
            float g = a*fg + (1 - a)*bg;
            float b = a*fb + (1 - a)*bb;
            ppm_set(px, py, rgb_join(r, g, b));
        }
    }
}

// Physics simulation

struct ball {
    struct v2 pos, vel;
    float r, m;
    int32_t color;
};

static void
ball_create(struct ball *b, uint64_t s[1])
{
    float r = rng(s, MINR, MAXR);
    // Drop just out view near the middle
    b->pos = (struct v2){rng(s, W/S*0.45f, W/S*0.55f), rng(s, -4*r, -2*r)};
    b->vel = (struct v2){rng(s, -0.2f, +0.2f), 0};
    b->r = r;
    b->m = PI * r * r;
    b->color = rng64(s)>>40 | 0x404040;
}

int
main(void)
{
#ifdef _WIN32
    /* Set stdout to binary mode. */
    int _setmode(int, int);
    _setmode(1, 0x8000);
#endif

    uint64_t s[1] = {hash64(hash64(time(0)) ^ clock())};

    struct ball balls[NBALLS+NPEGS];
    for (int i = 0; i < NBALLS; i++) {
        ball_create(balls + i, s);
    }

    // Initialize pegs (balls that don't move)
    for (int i = NBALLS, c = 0; i < NBALLS+NPEGS; i++, c++) {
        if (c % (2*PW) == 2*PW - 1) c++;
        int ix = (c % PW);
        int iy = (c / PW);
        float sx = W / S / PW;
        float sy = H / S / PH;
        float x = ix*sx + sx*0.5f + sx*(iy & 1 ? 0.5f : 0.0f);
        float y = iy*sy + sy*0.5f;
        balls[i].pos = (struct v2){x, y};
        balls[i].vel = (struct v2){0, 0};
        balls[i].r = PEGR;
        balls[i].m = 1.0f;
        balls[i].color = 0x4f4f4f;
    }

    long long hmax = 0;
    long long hist[NHIST] = {0};

    for (unsigned long long frame = 0; ; frame++) {

        // Ball simulation
        for (int a = 0; a < NBALLS; a++) {
            float ax = balls[a].pos.x;
            float ay = balls[a].pos.y;
            float ar = balls[a].r;

            // Completely below the display? Reset the ball.
            if (ay - ar*2 > H/S) {
                if (frame >= SKIP) {
                    int bin = ax / (W/S) * NHIST;
                    bin = bin < 0 ? 0 : bin >= NHIST ? NHIST-1 : bin;
                    long long h = ++hist[bin];
                    hmax = h > hmax ? h : hmax;
                }
                ball_create(balls + a, s);
                continue;
            }

            // Wall collisions
            if (ax + ar > W/S && balls[a].vel.x > 0) {
                balls[a].vel.x *= -E;
            } else if (ax - ar < 0 && balls[a].vel.x < 0) {
                balls[a].vel.x *= -E;
            }

            // Apply velocity and gravity
            balls[a].pos = v2_add(balls[a].pos, v2_scale(balls[a].vel, DT));
            balls[a].vel.y += DT * G * 0.5f;

            // Ball-to-ball/peg collisions
            for (int b = a + 1; b < NBALLS+NPEGS; b++) {
                struct v2 ap = balls[a].pos;
                struct v2 bp = balls[b].pos;
                float t = balls[a].r + balls[b].r;
                if (v2_dist2(ap, bp) < t*t) {
                    struct v2 n  = v2_normalize(v2_sub(bp, ap));
                    struct v2 av = balls[a].vel;
                    struct v2 bv = balls[b].vel;
                    float nv     = v2_dot(v2_sub(bv, av), n);

                    // Moving towards each other?
                    if (nv <= 0) {
                        float am = balls[a].m;
                        float bm = balls[b].m;
                        float j = -(1 + E)*nv / (1/am + 1/bm);
                        struct v2 i = v2_scale(n, j);
                        balls[a].vel = v2_sub(av, v2_scale(i, 1/am));
                        if (b < NBALLS) {
                            balls[b].vel = v2_add(bv, v2_scale(i, 1/bm));
                        }
                    }
                }
            }
        }

        if (frame < SKIP) {
            // Simulation still initializing
            continue;
        }

        ppm_clear();

        // Render histogram
        if (hmax) {
            for (int i = 0; i < NHIST; i++) {
                int w = W/NHIST;
                int h = hist[i] * (H/2) / hmax;
                for (int y = H - h; y < H; y++) {
                    for (int x = 0; x < w; x++) {
                        ppm_set(i*w + x, y, 0x3c3c3c);
                    }
                }
            }
        }

        // Render balls and pegs
        for (int i = 0; i < NBALLS+NPEGS; i++) {
            float x  = S*balls[i].pos.x;
            float y  = S*balls[i].pos.y;
            float r0 = S*balls[i].r * 0.9f;
            float r1 = S*balls[i].r * 1.1f;
            ppm_circle(x, y, r0, r1, balls[i].color);
        }

        if (!ppm_write()) {
            return 1;
        }
    }
}
