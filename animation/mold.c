// Probabilistic Rock-Paper-Scissors mold animation
//
// Usage:
//   $ cc -Ofast -o mold mold.c
//   $ ./mold | mpv --no-correct-pts --fps=60 --fs -
//   $ ./mold | x264 --frames=1800 --fps=60 -o mold.mp4 /dev/stdin
//
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <time.h>

#define S 2
#define W (1920/S)
#define H (1080/S)
static const float win_table[] = {.55f, .99f, 0.90f};
static const long colors[] = {0xfc766a, 0xb0b8b4, 0x184a45};

int
main(void)
{
    unsigned long long s = time(0);
    static unsigned char grid[H][W];

    #if _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            s = s*0x3243f6a8885a308dULL + 1;
            grid[y][x] = (s >> 32) % 3;
        }
    }

    for (;;) {
        s += (unsigned long long)clock();
        for (int i = 0; i < 1<<(16-S);) {
            s = s*0x3243f6a8885a308dULL + 1;

            int x0, y0, x1, y1, a, b;
            x1 = x0 = (s >> 32) % W;
            y1 = y0 = (s >> 48) % H;
            switch (s>>30 & 3) {
            case 0: x1 = (x1 +     1) % W; break;
            case 1: y1 = (y1 +     1) % H; break;
            case 2: x1 = (x1 + W - 1) % W; break;
            case 3: y1 = (y1 + H - 1) % H; break;
            }
            a = grid[y0][x0];
            b = grid[y1][x1];

            float r = (float)(s>>8 & 0xfffff)/(1L<<20);
            switch ((3 + a - b)%3) {
            case 1: if (r < win_table[b]) grid[y0][x0] = b;
                    else                  grid[y1][x1] = a;
                    i++; break;
            case 2: if (r < win_table[a]) grid[y1][x1] = a;
                    else                  grid[y0][x0] = b;
                    i++; break;
            }
        }

        static unsigned char canvas[H*S][W*S][3];
        for (int y = 0; y < H*S; y++) {
            for (int x = 0; x < W*S; x++) {
                long c = colors[grid[y/S][x/S]];
                canvas[y][x][0] = c >> 16;
                canvas[y][x][1] = c >>  8;
                canvas[y][x][2] = c >>  0;
            }
        }
        printf("P6\n%d %d\n255\n", W*S, H*S);
        if (!fwrite(canvas, sizeof(canvas), 1, stdout)) {
            return 1;
        }
    }
}
