/* Glitch video generator
 * $ cc -O3 -o glitch glitch.c
 * $ convert in.png ppm:- | ./glitch | x264 --fps 6 -o out.mp4 /dev/stdin
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define VSHIFT  12
#define HSHIFT  30
#define HRATE   30
#define NFRAMES 60

#define RANGE(s, min, max) (rnd(s) % ((max) - (min)) + (min))
static unsigned long
rnd(unsigned long long *s)
{
    *s = *s*0x9acb883ba7dad0ad + 1;
    return *s>>32 & 0xffffffff;
}

int
main(void)
{
    #ifdef _WIN32
    /* Set stdin/stdout to binary mode. */
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    int w, h;
    scanf("P6%d%d 255%*c", &w, &h);
    unsigned char *bufi = malloc(w*3L*h*2);
    unsigned char *bufo = bufi + w*3L*h;
    fread(bufi, w*3, h, stdin);
    unsigned long long s = time(0);

    for (int i = 0; i < NFRAMES; i++) {
        int rshift = h + RANGE(&s, -VSHIFT, +VSHIFT);
        int gshift = h + RANGE(&s, -VSHIFT, +VSHIFT);
        int bshift = h + RANGE(&s, -VSHIFT, +VSHIFT);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                bufo[y*w*3 + x*3 + 0] = bufi[(y+rshift)%h*w*3 + x*3 + 0];
                bufo[y*w*3 + x*3 + 1] = bufi[(y+gshift)%h*w*3 + x*3 + 1];
                bufo[y*w*3 + x*3 + 2] = bufi[(y+bshift)%h*w*3 + x*3 + 2];
            }
        }

        for (int y = 0; y < h; y++) {
            if (y == 0 || rnd(&s) % HRATE == 0) {
                rshift = RANGE(&s, -HSHIFT, +HSHIFT);
                gshift = RANGE(&s, -HSHIFT, +HSHIFT);
                bshift = RANGE(&s, -HSHIFT, +HSHIFT);
            }
            for (int x = 0; x < w; x++) {
                int ri = y*w*3 + (x+rshift+w)%w*3 + 0, rj = y*w*3 + x*3 + 0;
                int gi = y*w*3 + (x+rshift+w)%w*3 + 1, gj = y*w*3 + x*3 + 1;
                int bi = y*w*3 + (x+rshift+w)%w*3 + 2, bj = y*w*3 + x*3 + 2;
                bufo[ri < rj ? ri : rj] = bufo[ri < rj ? rj : ri];
                bufo[gi < gj ? gi : gj] = bufo[gi < gj ? gj : gi];
                bufo[bi < bj ? bi : bj] = bufo[bi < bj ? bj : bi];
            }
        }

        printf("P6\n%d %d\n255\n", w, h);
        fwrite(rnd(&s)&3 ? bufi : bufo, w*3, h, stdout);
    }
}
