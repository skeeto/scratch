// Starfield effect animation
//   $ cc -Ofast -o starfield starfield.c -lm
//   $ ./starfield | mpv --no-correct-pts --fps=60 --fs -
//   $ ./starfield | x264 --frames=1800 --fps=60 -o starfield.mp4 /dev/stdin
// Ref: https://old.reddit.com/r/proceduralgeneration/comments/wd03zw
// Ref: https://www.youtube.com/watch?v=p0I5bNVcYP8
// This is free and unencumbered software released into the public domain.
#include <math.h>
#include <stdio.h>
#include <time.h>

#define W    1920
#define H    1080
#define N    1600
#define FADE 8
#define MINA 1.005f
#define MODA 0.005f
#define STEP 0.008f
#define MIN(a, b) (a) < (b) ? (a) : (b)
#define MAX(a, b) (a) > (b) ? (a) : (b)
#define COUNTOF(a) (int)(sizeof(a)/sizeof(a[0]))
#define X(s) #s
#define S(s) X(s)

struct star {
    float px, py;
    float vx, vy;
    int age;
};

static struct star
new(unsigned long long *rng)
{
    unsigned long r = (*rng = *rng*0x3243f6a8885a308d + 1) >> 32;
    float x = ((r >> 16) & 0xffff) / 65536.0f * W;
    float y = ((r >>  0) & 0xffff) / 65536.0f * H;
    float a = atan2f(y-H/2, x-W/2);
    struct star s = {x, y, cosf(a), sinf(a), 0};
    return s;
}

static int
valid(int x, int y)
{
    return x >= 0 && y >= 0 && x < W && y < H;
}

int
main(void)
{
    static const int shape[] = {-1,0, +1,0, 0,0, 0,-1, 0,+1};
    static const char hdr[] = "P6\n"S(W)" "S(H)"\n255\n";
    static unsigned char ppm[H][W][3];
    unsigned long long rng[] = {time(0)};
    struct star stars[N];
    float t = 0.0f;
    int init = 64;

    #if _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    for (int i = 0; i < N; i++) {
        stars[i] = new(rng);
    }

    for (unsigned f = 0;; f++) {
        float acc = MINA + sinf(t)*MODA;
        t = fmodf(t+STEP, 2*3.14159265f);
        *rng += clock();

        // Blend transparent black over entire canvas
        for (int y = 0; y < H; y++) {
            for (int x = 0; x < W; x++) {
                ppm[y][x][0] = MAX(0, ppm[y][x][0]-FADE);
                ppm[y][x][1] = MAX(0, ppm[y][x][1]-FADE);
                ppm[y][x][2] = MAX(0, ppm[y][x][2]-FADE);
            }
        }

        // Draw each star and update
        for (int i = 0; i < N; i++) {
            int v = MIN(stars[i].age += 5, 255);
            for (int n = 0; n < COUNTOF(shape)/2; n++) {
                int x = shape[n*2+0] + stars[i].px;
                int y = shape[n*2+1] + stars[i].py;
                if (valid(x, y)) {
                    ppm[y][x][0] = ppm[y][x][1] = ppm[y][x][2] = v;
                }
            }
            stars[i].px += stars[i].vx;
            stars[i].py += stars[i].vy;
            stars[i].vx *= acc;
            stars[i].vy *= acc;
            if (!valid(stars[i].px, stars[i].py)) {
                stars[i] = new(rng);
            }
        }

        if (init) {
            // Let the starfield warm up before writing frames
            init--;
        } else if (f&1) {
            fwrite(hdr, sizeof(hdr)-1, 1, stdout);
            if (!fwrite(ppm, sizeof(ppm), 1, stdout)) {
                return 0;
            }
        }
    }
}
