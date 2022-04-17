// Random walk cave generator
//   $ cc -O3 -o cavewalk cavewalk.c
//   $ ./cavewalk | mpv --no-correct-pts --fps=30 -
//   $ ./cavewalk | x264 --fps=30 -o cavewalk.mp4 /dev/stdin
// Ref: https://old.reddit.com/r/roguelikedev/comments/u5kv9r/
#include <stdio.h>
#include <time.h>

#define W    128         // grid width
#define H    96          // grid height
#define S    8           // cell size (pixels)
#define FPS  30          // target frames per second
#define N    8           // max concurrent walkers
#define CW   0xff0000    // walker color
#define CB   0x101010    // filled color
#define CF   0x7f7f7f    // empty color

static unsigned char ppm[H*S][W*S][3];

static int
frame(void)
{
    printf("P6\n%d %d\n255\n", W*S, H*S);
    return fwrite(ppm, sizeof(ppm), 1, stdout);
}

static void
set(int x, int y, long c)
{
    if (x >= 0 && x < W && y >= 0 && y < H) {
        for (int py = 0; py < S; py++) {
            for (int px = 0; px < S; px++) {
                ppm[y*S+py][x*S+px][0] = c >> 16;
                ppm[y*S+py][x*S+px][1] = c >>  8;
                ppm[y*S+py][x*S+px][2] = c >>  0;
            }
        }
    }
}

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    unsigned long long rng = time(0);
    struct {
        int x, y;
        int age;
    } walkers[N];
    int nwalkers = 1;

    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            set(x, y, CB);
        }
    }

    walkers[0].x   = W/2;
    walkers[0].y   = H/2;
    walkers[0].age = 0;
    set(walkers[0].x, walkers[0].y, CW);

    while (nwalkers) {
        if (!frame()) return 1;

        for (int i = 0; i < nwalkers; i++) {
            set(walkers[i].x, walkers[i].y, CF);
            walkers[i].age++;
            rng = rng*0x3243f6a8885a308d + 1;

            static const int dir[][2] = {{+1,+0}, {-1,+0}, {+0,+1}, {+0,-1}};
            walkers[i].x += dir[rng>>62 & 3][0];
            walkers[i].y += dir[rng>>62 & 3][1];

            // Spawn a child?
            if (nwalkers < N && !(rng>>48 & 0x3f)) {
                int n = nwalkers++;
                walkers[n].x = walkers[i].x;
                walkers[n].y = walkers[i].y;
                walkers[n].age = walkers[i].age;
            }

            // Death by old age?
            if (((int)(rng>>32 & 0x3ff)+512) < walkers[i].age) {
                walkers[i--] = walkers[--nwalkers];
            }
        }

        for (int i = 0; i < nwalkers; i++) {
            set(walkers[i].x, walkers[i].y, CW);
        }
    }

    // Display the results for a few seconds
    for (int i = 0; i < FPS*3; i++) {
        if (!frame()) return 1;
    }
    return fflush(stdout);
}
