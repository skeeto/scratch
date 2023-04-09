// Growing plants animation
//   $ cc -O3 -o plants plants.c
//   $ ./plants | mpv --no-correct-pts --fps=60 -
// Ref: https://old.reddit.com/r/commandline/comments/12gq436
// Ref: https://github.com/VivekThazhathattil/boredom
// This is free and unencumbered software released into the public domain.
#include <stdio.h>

#define SCALE    4
#define WIDTH    (1280/SCALE)
#define HEIGHT   (720/SCALE)
#define NBRANCH  2
#define SPREAD   3
#define NPLANTS  ((WIDTH+SPREAD-1)/SPREAD+1)

static int rand31(unsigned long long *s)
{
    return (*s = *s*0x3243f6a8885a308d + 1) >> 33;
}

int main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    long colors[NPLANTS];
    static unsigned char grid[HEIGHT][WIDTH];
    unsigned long long rng = (unsigned long long)&rng;

    for (int ttl = 0;;) {
        if (!ttl) {  // reset?
            for (int y = 0; y < HEIGHT; y++) {
                for (int x = 0; x < WIDTH; x++) {
                    grid[y][x] = 0;
                }
            }
            ttl = 3*60;
            for (int x = 0; x < WIDTH; x++) {
                grid[HEIGHT-1][x] = x%SPREAD ? 0 : 1+x/SPREAD;
            }
            for (int i = 0; i < NPLANTS; i++) {
                colors[i] = rand31(&rng) | 0x404040;
            }
        }

        // Grow plants
        int updates = 0;
        int marks[NPLANTS] = {NBRANCH};
        for (int y = 0; y < HEIGHT; y++) {
            for (int x = 0; x < WIDTH; x++) {
                int e = grid[y][x];
                if (marks[e] == NBRANCH) continue;
                int dir = rand31(&rng)%3;
                static const int dirs[] = {+0,-1, -1,+0, +1,+0};
                int tx = x + dirs[dir*2+0];
                int ty = y + dirs[dir*2+1];
                if (tx>=0 && ty>=0 && tx<WIDTH && ty<HEIGHT && !grid[ty][tx]) {
                    grid[ty][tx] = e;
                    marks[e]++;
                    updates++;
                }
            }
        }
        ttl -= !updates;

        // Render system state as Netpbm
        static unsigned char ppm[SCALE*HEIGHT][SCALE*WIDTH][3];
        for (int y = 0; y < SCALE*HEIGHT; y++) {
            for (int x = 0; x < SCALE*WIDTH; x++) {
                int ci = grid[y/SCALE][x/SCALE];
                long c = ci ? colors[ci] : 0;
                ppm[y][x][0] = c >> 16;
                ppm[y][x][1] = c >>  8;
                ppm[y][x][2] = c >>  0;
            }
        }
        printf("P6\n%d %d\n255\n", SCALE*WIDTH, SCALE*HEIGHT);
        if (!fwrite(ppm, sizeof(ppm), 1, stdout)) {
            return 0;
        }
    }
}
