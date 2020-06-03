/* RANDU weakness demonstration
 * $ cc -Ofast -o randu randu.c -lm
 * $ ./randu | mpv --no-correct-pts --fps=60 -
 * $ ./randu | x264 --frames 720 --fps 60 -o randu.mp4 /dev/stdin
 * Ref: https://en.wikipedia.org/wiki/RANDU
 * Ref: https://nullprogram.com/blog/2017/11/03/
 * Ref: https://nullprogram.com/video/?v=randu
 * This is free and unencumbered software released into the public domain.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define W      1080
#define H      1080
#define N      (1L<<13)
#define SCALE  700.0f

static unsigned long randus = 1;
static long randu(void) { return (randus *= 0x10003) & 0x7fffffff; }

struct v2 { int x, y; };
struct v3 { float x, y, z; };

static struct v2
ortho(struct v3 p, float az, float el)
{
    float x = p.x*cosf(az) - p.y*sinf(az);
    float y = p.x*sinf(az) + p.y*cosf(az);
    return (struct v2){
        roundf(SCALE*x + W/2),
        roundf(SCALE*(y*sinf(el) + p.z*cosf(el)) + H/2)
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

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    #define PI 3.1415927f
    for (int az = 135;; az = (az + 1)%720) {
        clear();

        randus = 0x599103e3;
        for (long i = 0; i < N; i++) {
            struct v3 p3 = {
                randu()/2147483647.0f - 0.5f,
                randu()/2147483647.0f - 0.5f,
                randu()/2147483647.0f - 0.5f
            };
            struct v2 p2 = ortho(p3, az*PI/360, PI/6);
            point((struct v2){p2.x-1, p2.y+0}, 0xafafaf);
            point((struct v2){p2.x+1, p2.y+0}, 0xafafaf);
            point((struct v2){p2.x+0, p2.y-1}, 0xafafaf);
            point((struct v2){p2.x+0, p2.y+1}, 0xafafaf);
            point((struct v2){p2.x+0, p2.y+0}, 0xffffff);
        }

        static const unsigned long long font[] = {
            0xffc3c3ffd8ccc6c3, 0xffc3c3c3ffc3c3c3, 0xc3e3f3dbcfc7c3c3,
            0xfcc6c3c3c3c3c6fc, 0xc3c3c3c3c3c3c3ff
        };
        int p = 5;
        int s = 3;
        for (int i = 0; i < 5; i++) {
            for (int y = 0; y < 8*s; y++) {
                for (int x = 0; x < 8*s; x++) {
                    if (font[i]>>((7-y/s)*8+(7-x/s)) & 1) {
                        struct v2 p2 = {p + i*(8*s+p) + x, p + y};
                        point(p2, 0x00ff7f);
                    }
                }
            }
        }

        frame();
    }
}
