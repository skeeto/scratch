// Box pusher animation
// Green boxes randomly walk pushing blue boxes around.
//   $ cc -O3 -o boxes boxes.c
//   $ ./boxes | mpv --fps=15 --no-correct-pts -
//   $ ./boxes | x264 --frames=900 --fps=15 -o boxes.mp4 /dev/stdin
// Ref: https://old.reddit.com/r/proceduralgeneration/comments/wuriie
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <time.h>

#define W 30       // grid width
#define H 30       // grid height
#define S 20       // grid scale
#define N 100      // active boxes
#define R (15*60)  // simulation frames
enum {B_EMPTY, B_ACTIVE, B_PASSIVE};
static const int dir[] = {+1,+0, -1,+0, +0,+1, +0,-1};
static const long color[] = {0xffffff, 0x00ff00, 0x3f5fff, 0x2f2f2f};

struct sim {
    char grid[H][W];
    struct box {int x, y;} box[N];
};

static int
valid(int x, int y)
{
    return x>=0 && x<W && y>=0 && y<H;
}

static unsigned long
r32(unsigned long long *s)
{
    return ((*s = *s*0x3243f6a8885a308d + 1)>>32) & 0xffffffff;
}

static void
init(struct sim *s, unsigned long long *rng)
{
    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            s->grid[y][x] = B_EMPTY;
        }
    }

    // Populate with boxes
    for (int i = 0; i < 7*N; i++) {
        s->grid[i/H][i%W] = i%7 ? B_PASSIVE : B_ACTIVE;
    }

    // Shuffle the boxes
    for (int i = W*H-1; i > 1; i--) {
        int j = r32(rng) % (i + 1);
        char swap = s->grid[j/H][j%W];
        s->grid[j/H][j%W] = s->grid[i/H][i%W] ;
        s->grid[i/H][i%W] = swap;
    }

    // Find all the active boxes
    for (int y = 0, n = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            switch (s->grid[y][x]) {
            case B_ACTIVE:
                s->box[n].x = x;
                s->box[n++].y = y;
            }
        }
    }
}

int
main(void)
{
    struct sim s[1];
    unsigned long long rng[1] = {time(0)};

    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    for (unsigned long frame = 0;; frame++) {
        if (!(frame % R)) {
            init(s, rng);
        }

        for (int n = 0; n < N; n++) {
            int c = r32(rng) >> 30;
            int dx = dir[c*2+0], dy = dir[c*2+1];
            for (int d = 1;; d++) {
                int x = s->box[n].x + d*dx, y = s->box[n].y + d*dy;
                if (!valid(x, y) || s->grid[y][x] == B_ACTIVE) {
                    // Hard barrier, pass this turn
                    break;
                } else if (s->grid[y][x] == B_EMPTY) {
                    // Push passive boxes into empty space
                    s->grid[y][x] = B_PASSIVE;
                    s->grid[s->box[n].y][s->box[n].x] = B_EMPTY;
                    s->box[n].x += dx;
                    s->box[n].y += dy;
                    s->grid[s->box[n].y][s->box[n].x] = B_ACTIVE;
                    break;
                }
            }
        }

        static unsigned char ppm[S*H][S*W][3];
        for (int y = 0; y < H*S; y++) {
            for (int x = 0; x < W*S; x++) {
                int g = s->grid[y/S][x/S];
                ppm[y][x][0] = color[g] >> 16;
                ppm[y][x][1] = color[g] >>  8;
                ppm[y][x][2] = color[g] >>  0;
            }
        }
        for (int y = 1; y < H; y++) {
            for (int x = 0; x < S*W; x++) {
                ppm[y*S][x][0] = color[3] >> 16;
                ppm[y*S][x][1] = color[3] >>  8;
                ppm[y*S][x][2] = color[3] >>  0;
            }
        }
        for (int x = 1; x < W; x++) {
            for (int y = 0; y < S*H; y++) {
                ppm[y][x*S][0] = color[3] >> 16;
                ppm[y][x*S][1] = color[3] >>  8;
                ppm[y][x*S][2] = color[3] >>  0;
            }
        }
        printf("P6\n%d %d\n255\n", W*S, H*S);
        if (!fwrite(ppm, sizeof(ppm), 1, stdout)) {
            return 1;
        }
    }
}
