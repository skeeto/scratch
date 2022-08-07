// Nearest points to origin animation
//   $ cc -Ofast -o nearest nearest.c -lm
//   $ ./nearest | mpv --no-correct-pts --fps=60 --fs -
//   $ ./nearest | x264 --frames=1800 --fps=60 -o nearest.mp4 /dev/stdin
// This is free and unencumbered software released into the public domain.
#include <math.h>
#include <stdio.h>
#include <string.h>

#define N     (1<<16)
#define M     (1<<14)
#define SIZE  1080
#define X(s)  #s
#define S(s)  X(s)
#define COUNTOF(a) (int)(sizeof(a)/sizeof(*a))

struct point { float x, y; };

// Return the squared distance from the origin.
static float
dist2(struct point p)
{
    return p.x*p.x + p.y*p.y;
}

// Populate idx with the indices of the k points nearest to the origin.
static void
nearest(int *idx, int k, const struct point *points, int len)
{
    // Initialize idx as a max-heap from the first k elements.
    for (int i = 0; i < k && i < len; i++) {
        float d = dist2(points[i]);
        int n = i;
        idx[n] = i;
        while (n > 0) {  // down-heap
            int p = (n - 1) / 2;
            float dp = dist2(points[idx[p]]);
            if (d > dp) {
                int swap = idx[n];
                idx[n] = idx[p];
                idx[p] = swap;
                n = p;
            } else {
                break;
            }
        }
    }

    // Try to push all remaining points into the heap.
    float cutoff = k ? dist2(points[idx[0]]) : 0;
    for (int i = k; i < len; i++) {
        float d = dist2(points[i]);
        if (d >= cutoff) {
            continue;
        }

        int n = 0;
        idx[n] = i;
        for (;;) {  // down-up
            int a = 2*n + 1;
            int b = 2*n + 2;
            int j = n;
            if (b < k) {
                float da = dist2(points[idx[a]]);
                float db = dist2(points[idx[b]]);
                float td = da > db ? da : db;
                int   t  = da > db ?  a :  b;
                if (d < td) {
                    j = t;
                }
            } else if (a < k) {
                float da = dist2(points[idx[a]]);
                if (d < da) {
                    j = a;
                }
            }
            if (j == n) {
                break;
            }
            int swap = idx[n];
            idx[n] = idx[j];
            idx[j] = swap;
            n = j;
        }
        cutoff = dist2(points[idx[0]]);
    }
}

static struct point
randpoint(unsigned long long *s)
{
    struct point p;
    *s = *s*0x3243f6a8885a308d + 1;
    p.x = (unsigned)(*s >> 48 & 0xffff) / 32768.0f - 1;
    p.y = (unsigned)(*s >> 32 & 0xffff) / 32768.0f - 1;
    return p;
}

int main(void)
{
    unsigned long long rng[] = {0};
    static struct point p[N];

    #if _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    for (int i = 0; i < COUNTOF(p); i++) {
        p[i] = randpoint(rng);
    }

    for (;;) {
        for (int i = 0; i < COUNTOF(p); i++) {
            p[i].x *= 1.01f;
            p[i].y *= 1.01f;
            if (fabsf(p[i].x) > 1 || fabsf(p[i].y) > 1) {
                p[i] = randpoint(rng);
            }
        }

        int best[M];
        nearest(best, COUNTOF(best), p, COUNTOF(p));

        static unsigned char ppm[SIZE][SIZE][3];
        memset(ppm, 0, sizeof(ppm));

        // Color all points white
        for (int i = 0; i < COUNTOF(p); i++) {
            int x = p[i].x*SIZE/2 + SIZE/2;
            int y = p[i].y*SIZE/2 + SIZE/2;
            if (x >= 0 && x < SIZE && y >= 0 && y < SIZE) {
                ppm[y][x][0] = ppm[y][x][1] = ppm[y][x][2] = 255;
            }
        }

        // Color nearest points green
        for (int i = 0; i < COUNTOF(best); i++) {
            int x = p[best[i]].x*SIZE/2 + SIZE/2;
            int y = p[best[i]].y*SIZE/2 + SIZE/2;
            if (x >= 0 && x < SIZE && y >= 0 && y < SIZE) {
                ppm[y][x][0] = ppm[y][x][2] = 0;
            }
        }

        static const char hdr[] = "P6\n"S(SIZE)" "S(SIZE)"\n255\n";
        fwrite(hdr, sizeof(hdr)-1, 1, stdout);
        if (!fwrite(ppm, sizeof(ppm), 1, stdout)) {
            return 1;
        }
    }
}
