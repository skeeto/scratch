// Chaos Game animation
//   $ cc -Ofast -o chaosgame chaosgame.c
//   $ ./chaosgame | mpv --no-correct-pts --fps=60 --fs -
//   $ ./chaosgame | x264 --frames=900 --fps=60 -o chaosgame.mp4 /dev/stdin
// Ref: https://en.wikipedia.org/wiki/Chaos_game
// This is free and unencumbered software released into the public domain.
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define S     1080
#define SKIP  (1U<<8)

struct state {
    uint64_t s, i;
    double x, y;
};

static struct state
next(struct state s)
{
    // 8 edge points of the square
    static const float t[] = {
        0.0, 0.0,  0.5, 0.0,  1.0, 0.0,  0.0, 0.5,
        1.0, 0.5,  0.0, 1.0,  0.5, 1.0,  1.0, 1.0,
    };
    int r = (s.s = s.s*0x3243f6a8885a308dU + 1) >> 61;
    s.x += 2.0/3.0 * (t[r*2 + 0] - s.x);
    s.y += 2.0/3.0 * (t[r*2 + 1] - s.y);
    s.i++;
    return s;
}

static struct state
init(uint64_t seed)
{
    seed *= 1111111111111111111U; seed ^= seed >> 33;
    seed *= 1111111111111111111U; seed ^= seed >> 33;
    struct state s = {
        seed, 0,
        s.x = (seed & 0xffffffff)/4294967296.0,
        s.y = (seed >>        32)/4294967296.0,
    };
    s = next(s); s = next(s); s = next(s); s = next(s);
    s = next(s); s = next(s); s = next(s); s = next(s);
    return s;
}

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);  // stdout to binary mode
    #endif

    for (struct state s = init(time(0)); ; s = next(s)) {
        static unsigned char buf[S][S][3];
        buf[(int)(s.y*S)][(int)(s.x*S)][(s.s>>32)%3] = 255;
        if (!(s.i % SKIP)) {
            #define XSTR(s) STR(s)
            #define STR(s) #s
            static const char hdr[] = "P6\n" XSTR(S) " " XSTR(S) "\n255\n";
            if (!fwrite(hdr, sizeof(hdr)-1, 1, stdout) ||
                !fwrite(buf, sizeof(buf),   1, stdout)) {
                return 1;
            }
            s.s += clock();
        }
    }
}
