/* Glauber dynamics 2D ferromagnet temperature simulation
 * Usage:
 *   $ cc -Ofast -o magnet magnet.c -lm
 *   $ ./magnet | mpv --no-correct-pts --fps=60 -
 * Ref: http://bit-player.org/2019/glaubers-dynamics
 * Ref: https://nullprogram.com/video/?v=magnet
 * Ref: https://nullprogram.com/blog/2017/11/03/
 */
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>

#define WIDTH    256        /* State width */
#define HEIGHT   128        /* State height */
#define SCALE    6          /* Image scale */
#define IT       (1 << 15)  /* Simulation iterations per frame */
#define UP       0x410344L  /* Up color */
#define DOWN     0x713affL  /* Down color */
#define FONT     0xffffffL  /* Font color */
#define FSCALE   2          /* Font scaling */
#define PAD      4          /* Padding around temperature display */
#define TRATE    450.0      /* Temperature change rate */
#define TRANGE   2.0        /* Temperature "radius" */

static int
font(int c, int x, int y)
{
    /* 8x8 font data for "0123456789." */
    static const uint64_t font[] = {
        0x3c7e666666667e3c, 0x1838781818181818, 0x183c66460c183e7e,
        0x3c7e063c3c067e3c, 0x0c1c34647e0c0c0c, 0x7e7e607c7e067e3c,
        0x3c7e607c7e667e3c, 0x7e7e06060c0c1818, 0x3c7e663c3c667e3c,
        0x3c7e667e3e067e3c, 0x0000000000383838
    };
    uint64_t f = font[c == '.' ? 10 : c - '0'];
    return (f >> ((7 - y) * 8 + (7 - x))) & 1;
}

static uint64_t
xoshiro256ss(uint64_t s[4])
{
    uint64_t x = s[1] * 5;
    uint64_t r = ((x << 7) | (x >> 57)) * 9;
    uint64_t t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = (s[3] << 45) | (s[3] >> 19);
    return r;
}

static uint64_t
hash64(uint64_t x)
{
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    x ^= x >> 31;
    return x;
}

static double
uniform(uint64_t s[4])
{
    return xoshiro256ss(s) / (double)(uint64_t)-1;
}

int
main(void)
{
    long long nframe = 0;
    static signed char state[HEIGHT][WIDTH];
    static unsigned char image[HEIGHT * SCALE][WIDTH * SCALE][3];
    static const int dir[] = {-1, +0, +1, +0, +0, -1, +0, +1};
    uint64_t rng[4] = {
        0x329859bc4675bdc6, 0xc8cd487ab1164ed3,
        0x59ca17c678426562, 0x46ae0e996de88ef1
    };

#ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
#endif

    /* Initialize simulation state */
    rng[1] ^= hash64(time(0));
    for (int y = 0; y < HEIGHT; y++)
        for (int x = 0; x < WIDTH; x++)
            state[y][x] = xoshiro256ss(rng) & 0x10000 ? -1 : 1;

    for (;;) {
        double temperature = -sin(nframe++ / TRATE) * TRANGE + (TRANGE + 0.01);

        for (int i = 0; i < IT; i++) {
            /* Update a single spin */
            int sum = 0;
            uint64_t r = xoshiro256ss(rng);
            int x = (r & 0xffffffff) % WIDTH;
            int y = (r >> 32) % HEIGHT;
            for (int i = 0; i < 4; i++) {
                int nx = (WIDTH  + x + dir[i * 2 + 0]) % WIDTH;
                int ny = (HEIGHT + y + dir[i * 2 + 1]) % HEIGHT;
                sum += state[ny][nx];
            }
            int energy = 2 * state[y][x] * sum;
            if (energy < 0 || uniform(rng) < exp(-energy / temperature))
                state[y][x] = -state[y][x];
        }

        /* Render the state to the pixel buffer */
        for (int y = 0; y < HEIGHT * SCALE; y++) {
            for (int x = 0; x < WIDTH * SCALE; x++) {
                long color = state[y / SCALE][x / SCALE] < 0 ? DOWN : UP;
                image[y][x][0] = color >> 16;
                image[y][x][1] = color >>  8;
                image[y][x][2] = color >>  0;
            }
        }

        /* Render temperature reading to the pixel buffer */
        char buf[] = {
            '0' + (int)((temperature + 0.005) *   1.0) % 10,
            '.',
            '0' + (int)((temperature + 0.005) *  10.0) % 10,
            '0' + (int)((temperature + 0.005) * 100.0) % 10
        };
        for (int i = 0; i < (int)sizeof(buf); i++) {
            for (int y = 0; y < 8 * FSCALE; y++) {
                for (int x = 0; x < 8 * FSCALE; x++) {
                    if (font(buf[i], x / FSCALE, y / FSCALE)) {
                        int px = PAD + i * FSCALE * 8 + x;
                        int py = PAD + y;
                        long c = FONT;
                        image[py][px][0] = c >> 16;
                        image[py][px][1] = c >>  8;
                        image[py][px][2] = c >>  0;
                    }
                }
            }
        }

        /* Write frame to stdout */
        printf("P6\n%d %d\n255\n", WIDTH * SCALE, HEIGHT * SCALE);
        if (!fwrite(image, sizeof(image), 1, stdout))
            break;
    }
}
