/* Strange attractor (ODE system) animator
 * $ cc -DLORENZ -Ofast -o attractors attractors.c -lm
 * $ ./attractors | mpv --no-correct-pts --fps=60 --fs -
 * $ ./attractors | x264 --fps 60 --frames 3600 -o attractors.mp4 /dev/stdin
 * Ref: https://www.dynamicmath.xyz/strange-attractors/
 * This is free and unencumbered software released into the public domain.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define W      1920
#define H      1080

#if defined(LORENZ)
#  define N      256
#  define TAIL   128
#  define SCALE  20.0f
#  define SIGMA  10.0f
#  define BETA   8.0f/3.0f
#  define RHO    28.0f
#  define DT     0.004f
#  define DX(x, y, z) SIGMA*(y - x)
#  define DY(x, y, z) x*(RHO - z) - y
#  define DZ(x, y, z) x*y - BETA*z
#  define X0 rnd(-10,+10)
#  define Y0 rnd(-10,+10)
#  define Z0 rnd(-10,+10) + RHO
#  define TX 0
#  define TY 0
#  define TZ -RHO

#elif defined(SPROTT)
#  define N     256
#  define TAIL  64
#  define SCALE 280.0f
#  define A     2.07f
#  define B     1.79f
#  define DT    0.02f
#  define DX(x, y, z) y + A*x*y + x*z
#  define DY(x, y, z) 1 - B*x*x + y*z
#  define DZ(x, y, z) x - x*x - y*y
#  define X0 rnd(-1, +1);
#  define Y0 rnd(-1, +1);
#  define Z0 rnd(-1, +1);
#  define TX 0
#  define TY 0
#  define TZ 0

#elif defined(AIZAWA)
#  define N     512
#  define TAIL  32
#  define SCALE 360.0f
#  define A     0.95f
#  define B     0.7f
#  define C     0.6f
#  define D     3.5f
#  define E     0.25f
#  define F     0.1f
#  define DT    0.01f
#  define DX(x, y, z) (z - B)*x - D*y
#  define DY(x, y, z) D*x + (z - B)*y
#  define DZ(x, y, z) C + A*z - z*z*z/3 - (x*x + y*y)*(1 + E*z) + F*z*x*x*x
#  define X0 rnd(-1, +1)
#  define Y0 rnd(-1, +1)
#  define Z0 rnd(-1, +1) + B
#  define TX 0
#  define TY 0
#  define TZ -B

#elif defined(HALVORSEN)
#  define N     512
#  define TAIL  32
#  define SCALE 36.0f
#  define A     sqrtf(2)
#  define DT    0.004f
#  define DX(x, y, z) -A*x - 4*y - 4*z - y*y
#  define DY(x, y, z) -A*y - 4*z - 4*x - z*z
#  define DZ(x, y, z) -A*z - 4*x - 4*y - x*x
#  define X0 rnd(-4, +4)
#  define Y0 rnd(-2, -1)
#  define Z0 rnd(-2, +2)
#  define TX 0
#  define TY 0
#  define TZ 0

#elif defined(DADRAS)
#  define N     512
#  define TAIL  128
#  define SCALE 40.0f
#  define A     3.0f
#  define B     2.7f
#  define C     1.7f
#  define D     2.0f
#  define E     9.0f
#  define DT    0.0025f
#  define DX(x, y, z) y - A*x + B*y*z
#  define DY(x, y, z) D*x*z - E*y
#  define DZ(x, y, z) C*z - x*y + y
#  define X0 rnd(-8, +8)
#  define Y0 rnd(-8, +8)
#  define Z0 rnd(-8, +8)
#  define TX 0
#  define TY 0
#  define TZ 0

#elif defined(THOMAS)
#  define N     512
#  define TAIL  32
#  define SCALE 120.0f
#  define B     0.208186f
#  define DT    0.04f
#  define DX(x, y, z) sinf(y) - B*x
#  define DY(x, y, z) sinf(z) - B*y
#  define DZ(x, y, z) sinf(x) - B*z
#  define X0 rnd(-4, +4)
#  define Y0 rnd(-4, +4)
#  define Z0 rnd(-4, +4)
#  define TX 0
#  define TY 0
#  define TZ 0

#else
#  error  Define LORENZ, SPROTT, AIZAWA, HALVORSEN, or THOMAS
#endif

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

static struct v2
ortho(struct v3 p, float scale, float az, float el)
{
    float x = p.x*cosf(az) - p.y*sinf(az);
    float y = p.x*sinf(az) + p.y*cosf(az);
    return (struct v2){
        roundf(scale*x + W/2),
        roundf(scale*(y*sinf(el) + p.z*cosf(el)) + H/2)
    };
}

static unsigned char buf[H][W][3];

static void
clear(void)
{
    memset(buf, 0, sizeof(buf));
}

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
    if (!fwrite(header, sizeof(header) - 1, 1, stdout) ||
        !fwrite(buf, sizeof(buf), 1, stdout)) {
        exit(1);
    }
}

static struct v3
step(struct v3 v)
{
    float x = v.x;
    float y = v.y;
    float z = v.z;

    float k1dx = DX(x, y, z);
    float k1dy = DY(x, y, z);
    float k1dz = DZ(x, y, z);

    float k2x = x + k1dx*DT/2;
    float k2y = y + k1dy*DT/2;
    float k2z = z + k1dz*DT/2;

    float k2dx = DX(k2x, k2y, k2z);
    float k2dy = DY(k2x, k2y, k2z);
    float k2dz = DZ(k2x, k2y, k2z);

    float k3x = x + k2dx*DT/2;
    float k3y = y + k2dy*DT/2;
    float k3z = z + k2dz*DT/2;

    float k3dx = DX(k3x, k3y, k3z);
    float k3dy = DY(k3x, k3y, k3z);
    float k3dz = DZ(k3x, k3y, k3z);

    float k4x = x + k3dx*DT;
    float k4y = y + k3dy*DT;
    float k4z = z + k3dz*DT;

    float k4dx = DX(k4x, k4y, k4z);
    float k4dy = DY(k4x, k4y, k4z);
    float k4dz = DZ(k4x, k4y, k4z);

    struct v3 r = {
        x + (k1dx + 2*k2dx + 2*k3dx + k4dx) * DT / 6,
        y + (k1dy + 2*k2dy + 2*k3dy + k4dy) * DT / 6,
        z + (k1dz + 2*k2dz + 2*k3dz + k4dz) * DT / 6,
    };
    return r;
}

static struct v3
translate(struct v3 v)
{
    v.x += TX;
    v.y += TY;
    v.z += TZ;
    return v;
}

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000); /* set stdout to binary mode */
    #endif

    struct {
        long color;
        int head, tail;
        struct v3 pos[TAIL];
    } points[N];

    u32s = time(0);
    for (int i = 0; i < N; i++) {
        points[i].color = u32()>>8 | 0x404040;
        points[i].head = points[i].tail = 0;
        points[i].pos[0].x = X0;
        points[i].pos[0].y = Y0;
        points[i].pos[0].z = Z0;
    }

    float az = rnd(-PI, PI);
    float elv = rnd(-PI, PI);

    for (;;) {
        clear();

        float el = sinf(elv)*0.5f;
        for (int i = 0; i < N; i++) {
            int head = (points[i].head + 1)%TAIL;
            int tail = points[i].tail;
            if (head == tail) {
                tail = (tail + 1)%TAIL;
            }
            points[i].pos[head] = step(points[i].pos[points[i].head]);
            points[i].head = head;
            points[i].tail = tail;

            for (int j = head; j != tail; j = (j + TAIL - 1)%TAIL) {
                struct v3 h = translate(points[i].pos[j]);
                struct v3 t = translate(points[i].pos[(j+TAIL-1)%TAIL]);
                struct v2 a = ortho(h, SCALE, az, el);
                struct v2 b = ortho(t, SCALE, az, el);
                line(a, b, points[i].color);
            }

            struct v3 h = translate(points[i].pos[head]);
            struct v2 r = ortho(h, SCALE, az, el);
            point((struct v2){r.x+1, r.y+0}, points[i].color);
            point((struct v2){r.x-1, r.y+0}, points[i].color);
            point((struct v2){r.x+0, r.y+1}, points[i].color);
            point((struct v2){r.x+0, r.y-1}, points[i].color);
        }

        frame();

        az += 0.0027f;
        elv += 0.01f;
    }
}
