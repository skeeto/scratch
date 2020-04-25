/* Sandpiles identity compute and render
 * Many piles are processed in parallel using AVX2 and OpenMP.
 *
 *   $ cc -O3 -march=native -fopenmp sandpiles.c
 *   $ ./a.out >identity.ppm
 *
 *   $ cc -O3 -march=native -DANIMATE -DN=64 -DSCALE=16 sandpiles.c
 *   $ ./a.out | mpv --no-correct-pts --fps=20 -
 *
 * Ref: https://www.youtube.com/watch?v=1MtEUErz7Gg
 * Ref: https://codegolf.stackexchange.com/a/106990
 * Ref: https://nullprogram.com/blog/2017/11/03/
 * Ref: https://nullprogram.com/blog/2015/07/10/
 * Ref: https://www.youtube.com/watch?v=hBdJB-BzudU
 */
#include <stdio.h>
#include <string.h>

#ifndef N
#  define N 1000
#endif
#ifndef SCALE
#  define SCALE 1
#endif

/* Color palette */
#define C0 0xff9200
#define C1 0xf53d52
#define C2 0xfce315
#define C3 0x44c5cb
#define CX 0x000000

#ifdef __AVX2__
#  include <immintrin.h>
#  define TAILSTART N/32*32
#else
#  warning Not using AVX2!
#  define TAILSTART 0
#endif

static char state[2][2+N+31][2+N+31];

static void
render(void)
{
    static unsigned char buf[3L*N*SCALE*N*SCALE];
    static const long colors[] = {C0, C1, C2, C3};
    for (int y = 0; y < N*SCALE; y++) {
        for (int x = 0; x < N*SCALE; x++) {
            int v = state[0][1+y/SCALE][1+x/SCALE];
            long c = v < 4 ? colors[v] : CX;
            buf[y*3L*SCALE*N + x*3L + 0] = c >> 16;
            buf[y*3L*SCALE*N + x*3L + 1] = c >>  8;
            buf[y*3L*SCALE*N + x*3L + 2] = c >>  0;
        }
    }
    printf("P6\n%d %d\n255\n", N*SCALE, N*SCALE);
    fwrite(buf, sizeof(buf), 1, stdout);
}

static void
stabilize(void)
{
    for (int n = 0; ; n = !n) {
        long spills = 0;

        int y; // To satisfy Visual Studio's OpenMP limitations :-(
        #pragma omp parallel for
        for (y = 0; y < N; y++) {
            int xspills = 0;

            #ifdef __AVX2__
            for (int x = 0; x < N/32*32; x += 32) {
                __m256i v = _mm256_loadu_si256((void *)&state[n][1+y][1+x]);
                __m256i m = _mm256_cmpgt_epi8(v, _mm256_set1_epi8(3));
                __m256i s = _mm256_sub_epi8(v, _mm256_set1_epi8(4));
                __m256i r = _mm256_blendv_epi8(v, s, m);
                xspills += !_mm256_testz_si256(m, m);

                v = _mm256_loadu_si256((void *)&state[n][1+y-1][1+x]);
                m = _mm256_cmpgt_epi8(v, _mm256_set1_epi8(3));
                s = _mm256_add_epi8(r, _mm256_set1_epi8(1));
                r = _mm256_blendv_epi8(r, s, m);

                v = _mm256_loadu_si256((void *)&state[n][1+y+1][1+x]);
                m = _mm256_cmpgt_epi8(v, _mm256_set1_epi8(3));
                s = _mm256_add_epi8(r, _mm256_set1_epi8(1));
                r = _mm256_blendv_epi8(r, s, m);

                v = _mm256_loadu_si256((void *)&state[n][1+y][1+x-1]);
                m = _mm256_cmpgt_epi8(v, _mm256_set1_epi8(3));
                s = _mm256_add_epi8(r, _mm256_set1_epi8(1));
                r = _mm256_blendv_epi8(r, s, m);

                v = _mm256_loadu_si256((void *)&state[n][1+y][1+x+1]);
                m = _mm256_cmpgt_epi8(v, _mm256_set1_epi8(3));
                s = _mm256_add_epi8(r, _mm256_set1_epi8(1));
                r = _mm256_blendv_epi8(r, s, m);

                _mm256_storeu_si256((void *)&state[!n][1+y][1+x], r);
            }
            #endif

            for (int x = TAILSTART; x < N; x++) {
                int v = state[n][1+y][1+x];
                int r = v < 4 ? v : v - 4;
                xspills += v >= 4;
                r += state[n][1+y-1][1+x] >= 4;
                r += state[n][1+y+1][1+x] >= 4;
                r += state[n][1+y][1+x-1] >= 4;
                r += state[n][1+y][1+x+1] >= 4;
                state[!n][1+y][1+x] = r;
            }

            #pragma omp atomic
            spills += xspills;
        }

        #ifdef ANIMATE
        render();
        #endif

        if (!spills) {
            return;
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

    for (int y = 0; y < N; y++) {
        for (int x = 0; x < N; x++) {
            state[0][1+y][1+x] = 6;
        }
    }
    stabilize();
    for (int y = 0; y < N; y++) {
        for (int x = 0; x < N; x++) {
            state[0][1+y][1+x] = 6 - state[0][1+y][1+x];
        }
    }
    stabilize();
    render();

    #ifdef ANIMATE
    for (int i = 0; i < 180; i++) render();
    #endif
}
