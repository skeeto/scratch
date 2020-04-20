/* Random walkers
 * $ cc -O3 -o walkers walkers.c
 * $ (while ./walkers; do :; done) | mpv --no-correct-pts --fps=60 -
 * $ ./walkers | x264 --fps 60 -o walkers.mp4 /dev/stdin
 * Ref: https://redd.it/g49qwk
 * Ref: https://nullprogram.com/video/?v=walk2d
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#define N 256
#define W 1920
#define H 1080
#define R 3

static unsigned long long u32s;
static unsigned long
u32(void) { return (u32s = u32s*0xf81eaa63f19f724d + 1)>>32 & 0xffffffff; }

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    static unsigned char tails[H*3L*W];
    static unsigned char output[H*3L*W];
    static struct { short x, y; char dir, len, color; } walkers[N];
    static const int dirs[] = {
        +0, -1, +1, -1, +1, +0, +1, +1, +0, +1, -1, +1, -1, +0, -1, -1
    };
    static const long colors[] = {
        0xffffff, 0x000000, 0xff0000, 0x7f0000, 0xff7f00, 0xffff7f
    };

    u32s = time(0);
    for (int i = 0; i < N; i++) {
        walkers[i].x = W / 2;
        walkers[i].y = H / 2;
        walkers[i].color = u32() % 6;
        walkers[i].dir = u32() % 8;
    }

    memset(tails, 0x7f, sizeof(tails));

    for (int n = 0; n < 30*60; n++) {
        for (int i = 0; i < N; i++) {
            if (!walkers[i].len--) {
                unsigned long r = u32();
                walkers[i].len = (r >> 27) + 16;
                walkers[i].dir = (walkers[i].dir + r%3 + 7) % 8;
            }

            walkers[i].x = (walkers[i].x + dirs[walkers[i].dir*2 + 0] + W) % W;
            walkers[i].y = (walkers[i].y + dirs[walkers[i].dir*2 + 1] + H) % H;

            long c = colors[walkers[i].color];
            tails[walkers[i].y*3L*W + walkers[i].x*3L + 0] = c >> 16;
            tails[walkers[i].y*3L*W + walkers[i].x*3L + 1] = c >>  8;
            tails[walkers[i].y*3L*W + walkers[i].x*3L + 2] = c >>  0;
        }

        memcpy(output, tails, sizeof(output));
        for (int i = 0; i < N; i++) {
            for (int y = walkers[i].y - R; y <= walkers[i].y + R; y++) {
                for (int x = walkers[i].x - R; x <= walkers[i].x + R; x++) {
                    if (x >= 0 && x < W && y >= 0 && y < H) {
                        long c = colors[walkers[i].color];
                        output[y*3L*W + x*3L + 0] = c >> 16;
                        output[y*3L*W + x*3L + 1] = c >>  8;
                        output[y*3L*W + x*3L + 2] = c >>  0;
                    }
                }
            }
        }

        printf("P6\n%d %d\n255\n", W, H);
        if (!fwrite(output, sizeof(output), 1, stdout)) return 1;
        u32s += clock() * 0xadb53df30b73119dULL;
        u32s ^= u32s >> 32;
    }
}
