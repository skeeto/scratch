/* Mersenne Twister visualization
 * $ cc -O3 -o mtvisualize mtvisualize.c
 * $ ./mtvisualize | mpv -
 * $ ./mtvisualize | x264 -o video.mp4 /dev/stdin
 * http://nullprogram.com/video/?v=mt19937-shuffle
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CON    0x444444
#define COFF   0xffffff
#define ROWS   125
#define COLS   5
#define WIDTH  (COLS * 33 - 1)
#define HEIGHT (ROWS)
#define SCALE  6

static unsigned char image[SCALE * WIDTH * 3 * SCALE * HEIGHT];

static void
set(int x, int y, unsigned long c)
{
    for (int sy = 0; sy < SCALE; sy++) {
        int yy = y * SCALE + sy;
        for (int sx = 0; sx < SCALE; sx++) {
            unsigned char *p;
            int xx = x * SCALE + sx;
            p = image + yy * WIDTH * SCALE * 3 + xx * 3;
            p[0] = c >>  0;
            p[1] = c >>  8;
            p[2] = c >> 16;
        }
    }
}

static void
draw_int(int x, int y, uint32_t v, unsigned long on, unsigned long off)
{
    for (int i = 0; i < 32; i++)
        set(x + (31 - i), y, (v >> i) & 1 ? on : off);
}

#define MT_W  32
#define MT_N  624
#define MT_M  397
#define MT_R  31
#define MT_A  UINT32_C(0x9908b0df)
#define MT_U  11
#define MT_D  UINT32_C(0xffffffff)
#define MT_S  7
#define MT_B  UINT32_C(0x9d2c5680)
#define MT_T  15
#define MT_C  UINT32_C(0xefc60000)
#define MT_L  18
#define MT_F  UINT32_C(1812433253)
#define MT_LM ((UINT32_C(1) << MT_R) - 1)
#define MT_UM (~MT_LM)

struct mt {
    uint32_t v[MT_N];
    int i;
};

static void
draw(struct mt *mt, int m, int n, int o)
{
    draw_int(0, 0, mt->i, CON, COFF);
    for (int i = 0; i < 624; i++) {
        int x = (i + 1) / ROWS;
        int y = (i + 1) % ROWS;
        unsigned long con  = CON;
        unsigned long coff = COFF;
        if (i == m) {
            con  |= 0xff0000;
            coff |= 0xffaaaa;
        } else if (i == n) {
            con  |= 0x00ff00;
            coff |= 0xaaffaa;
        } else if (i == o) {
            con  |= 0x0000ff;
            coff |= 0xaaaaff;
        }
        draw_int(x * 33, y, mt->v[i], con, coff);
    }
    printf("P6\n%d %d\n255\n", WIDTH * SCALE, HEIGHT * SCALE);
    if (!fwrite(image, sizeof(image), 1, stdout)) exit(1);
}

static void
mt_init(struct mt *mt, uint32_t seed)
{
    mt->i = MT_N;
    mt->v[0] = seed;
    for (int i = 1; i < MT_N; i++)
        mt->v[i] = MT_F * (mt->v[i - 1] ^ (mt->v[i - 1] >> (MT_W - 2))) + i;
}

static uint32_t
mt_rand(struct mt *mt)
{
    if (mt->i >= MT_N) {
        /* Draw BEGIN */
            draw(mt, -1, -1, -1);
        /* Draw END */
        for (int i = 0; i < MT_N; i++) {
            uint32_t x = (mt->v[i] & MT_UM) + (mt->v[(i + 1) % MT_N] & MT_LM);
            uint32_t xa = (x >> 1) ^ ((x & 1) * MT_A);
            mt->v[i] = mt->v[(i + MT_M) % MT_N] ^ xa;
            /* Draw BEGIN */
                mt->i = i;
                draw(mt, i, (i + 1) % MT_N, (i + MT_M) % MT_N);
            /* Draw END */
        }
        mt->i = 0;
        /* Draw BEGIN */
            draw(mt, -1, -1, -1);
        /* Draw END */
    }
    uint32_t y = mt->v[mt->i++];
    y = y ^ ((y >> MT_U) & MT_D);
    y = y ^ ((y << MT_S) & MT_B);
    y = y ^ ((y << MT_T) & MT_C);
    y = y ^ (y >> MT_L);
    return y;
}

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    memset(image, 0xff, sizeof(image));

    struct mt mt[1] = {{{0}, 0}};
    mt_init(mt, 1131464071);
    mt_rand(mt);
}
