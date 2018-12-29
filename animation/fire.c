/* Usage:
 *   $ cc -O -o fire fire.c
 *   $ ./fire | mpv -
 * Ref: https://github.com/fabiensanglard/DoomFirePSX/blob/master/flames.html
 * Ref: https://nullprogram.com/video/?v=fire
 */
#include <time.h>
#include <stdio.h>

#define W 200
#define H 120
#define S 6    /* pixel size */
#define D (sizeof(palette) / sizeof(*palette) / 3)

static const unsigned char palette[] = {
    0x07, 0x07, 0x07, 0x1F, 0x07, 0x07, 0x2F, 0x0F, 0x07, 0x47, 0x0F, 0x07,
    0x57, 0x17, 0x07, 0x67, 0x1F, 0x07, 0x77, 0x1F, 0x07, 0x8F, 0x27, 0x07,
    0x9F, 0x2F, 0x07, 0xAF, 0x3F, 0x07, 0xBF, 0x47, 0x07, 0xC7, 0x47, 0x07,
    0xDF, 0x4F, 0x07, 0xDF, 0x57, 0x07, 0xDF, 0x57, 0x07, 0xD7, 0x5F, 0x07,
    0xD7, 0x5F, 0x07, 0xD7, 0x67, 0x0F, 0xCF, 0x6F, 0x0F, 0xCF, 0x77, 0x0F,
    0xCF, 0x7F, 0x0F, 0xCF, 0x87, 0x17, 0xC7, 0x87, 0x17, 0xC7, 0x8F, 0x17,
    0xC7, 0x97, 0x1F, 0xBF, 0x9F, 0x1F, 0xBF, 0x9F, 0x1F, 0xBF, 0xA7, 0x27,
    0xBF, 0xA7, 0x27, 0xBF, 0xAF, 0x2F, 0xB7, 0xAF, 0x2F, 0xB7, 0xB7, 0x2F,
    0xB7, 0xB7, 0x37, 0xCF, 0xCF, 0x6F, 0xDF, 0xDF, 0x9F, 0xEF, 0xEF, 0xC7,
    0xFF, 0xFF, 0xFF
};

static long rng;
static char fire[H][W];

static unsigned long
rand31(void)
{
    /* Park-Miller LCG */
    long hi = rng / 127773L;
    long lo = rng % 127773L;
    long t  = 16807L * lo - 2836L * hi;
    rng = t > 0 ? t : t + 2147483647L;
    return rng;
}

static int
max(int a, int b)
{
    return b > a ? b : a;
}

static int
print(void)
{
    int x, y;
    static unsigned char image[W * S * H * S * 3];
    printf("P6\n%d %d\n255\n", W * S, H * S);
    for (y = 0; y < H * S; y++) {
        for (x = 0; x < W * S; x++) {
            const unsigned char *rgb = palette + fire[y / S][x / S] * 3;
            unsigned char *dst = image + y * W * S * 3 + x * 3;
            dst[0] = rgb[0];
            dst[1] = rgb[1];
            dst[2] = rgb[2];
        }
    }
    return !fwrite(image, sizeof(image), 1, stdout);
}

static void
step(void)
{
    int x, y;
    for (y = H - 2; y >= 0; y--) {
        for (x = 0; x < W; x++) {
            unsigned long r = rand31() >> 16;
            int s = r & 1;
            int d = (r >> 1) & 3;
            fire[y][(x + W + d - 1) % W] = max(fire[y + 1][x] - s, 0);
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

    long c;
    rng = time(0);
    for (c = 0; ; c++) {
        switch (c % 150) {
            int x;
            case 90:
                for (x = 0; x < W; x++)
                    fire[H - 1][x] = 0;
                break;
            case 0:
                for (x = 0; x < W; x++)
                    fire[H - 1][x] = D - 1;
                break;
        }
        step();
        if (print()) return 1;
    }
    return 0;
}
