/* Visualization of 4d6-drop-1 distribution
 *   $ cc -Ofast -o 4d6drop1 4d6drop1.c
 *   $ ./4d6drop1 | mpv --no-correct-pts --fps=60 -
 *   $ ./4d6drop1 | x264 --fps=60 --frames=3600 -o 4d6drop1.mp4 /dev/stdin
 * Ref: https://redd.it/kgvpj2
 * This is free and unencumbered software released into the public domain.
 */
#include <stdio.h>
#include <string.h>

#define W  1920
#define H  1080
#define C  0x5eff7e

static unsigned long
d6(void)
{
    static unsigned long long s = 1;
    for (;;) {
        s = s*0x2ab97a6e1147dde5ULL + 1;
        unsigned long r = s>>32 & 0xffffffff;
        r ^= r >> 16;
        r *= 0xec03deb7;
        r &= 0xffffffff;
        r ^= r >> 16;
        if (r < 0xfffffffc) return 1 + r%6;
    }
}

int
main(void)
{
#ifdef _WIN32
    /* Set stdout to binary mode. */
    int _setmode(int, int);
    _setmode(1, 0x8000);
#endif

    long long high = 0;
    long long hist[1+3*6] = {0};

    for (long long n = 0; ; n++) {
        int rolls[4] = {d6(), 0, 0, 0};
        for (int j = 1; j < 4; j++) {
            int r = d6();
            if (rolls[0] > r) {
                rolls[j] = rolls[0];
                rolls[0] = r;
            } else {
                rolls[j] = r;
            }
        }
        int i = rolls[1]+rolls[2]+rolls[3];
        long long v = ++hist[i];
        high = v > high ? v : high;

        /* Render */
        if (n & 0x3) continue;  // skip frames
        static unsigned char im[H][W][3];
        memset(im, 0, sizeof(im));
        for (int i = 3*1; i <= 3*6; i++) {
            int h = 0.98 * H * hist[i] / high;
            int w = W/16;
            int pad = W/256;
            for (int y = 0; y < h; y++) {
                for (int x = pad; x < w - pad; x++) {
                    im[H-y-1][x+(i-3)*w][0] = (unsigned char)(C >> 16);
                    im[H-y-1][x+(i-3)*w][1] = (unsigned char)(C >>  8);
                    im[H-y-1][x+(i-3)*w][2] = (unsigned char)(C >>  0);
                }
            }
        }
        printf("P6\n%d %d\n255\n", W, H);
        if (!fwrite(im, sizeof(im), 1, stdout)) return 1;
    }
}
