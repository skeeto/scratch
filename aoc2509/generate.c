#include <stdint.h>
#include "aoc2509.c"

static float isin_table(int i)
{
    static uint16_t table[64] = {
        +   0, +1608,  3216,  4821,  6424,  8022,  9616, 11204,
        12785, 14359, 15924, 17479, 19024, 20557, 22078, 23586,
        25080, 26558, 28020, 29466, 30893, 32303, 33692, 35062,
        36410, 37736, 39040, 40320, 41576, 42806, 44011, 45190,
        46341, 47464, 48559, 49624, 50660, 51665, 52639, 53581,
        54491, 55368, 56212, 57022, 57798, 58538, 59244, 59914,
        60547, 61145, 61705, 62228, 62714, 63162, 63572, 63944,
        64277, 64571, 64827, 65043, 65220, 65358, 65457, 65516,
    };
    float div = 65'536;
    if (i < 64) {
        return table[i] / div;
    } else if (i < 128) {
        return table[127-i] / div;
    } else if (i < 192) {
        return table[i-128] / -div;
    } else {
        return table[255-i] / -div;
    }
}

static float isin(float x)
{
    float a = __builtin_fmodf(x, 1) * 256;
    int   i = (int)(a + 0);
    int   j = (int)(a + 1) % 256;
    float s = a - (float)i;
    float n = (float)isin_table(i);
    float m = (float)isin_table(j);
    return (1 - s)*n + s*m;
}

static float icos(float x)
{
    return isin(x+.25f);
}

static int32_t randint(uint64_t *rng, int32_t lo, int32_t hi)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return (int32_t)(((*rng>>32) * (uint64_t)(hi - lo))>>32) + lo;
}

static V2s generate(uint64_t seed, Arena *a)
{
    enum {
        midx   = 50'000,
        midy   = 50'000,
        radius = 48'000,
        delta  =  1'000,
    };

    V2       pos   = {};
    int32_t  save  = 0;
    uint64_t rng   = seed;
    int32_t  count = 256 + randint(&rng, -16, 16);

    V2s r = {};
    r.data = new(a, 2*count, V2);

    for (int i = 0 ; i < count; i++) {
        float a = (float)i / (float)count;

        pos.x = (int32_t)((float)radius*icos(a) + (float)midx + .5f);
        if (a>=.875f || a<.125f || (a>=.375f && a<.625f)) {
            pos.x += randint(&rng, 1, delta);
        }

        if (i == count/2) {
            pos.x = 2*midx - pos.x - 2*delta;
        }

        if (i) {
            r.data[r.len++] = pos;
        }

        pos.y = (int32_t)((float)radius*isin(a) + (float)midy + .5f);
        if ((a>=.125f && a<.375f) || (a>=.625f && a<.875f)) {
            pos.y += randint(&rng, 1, delta);
        }

        if (i == count/2) {
            pos.y = midy - delta/2;
        }

        if (i == 0) {
            save = pos.y;
        } else if (i == count-1) {
            pos.y = save;
        }
        if (i) {
            r.data[r.len++] = pos;
        }
    }

    return r;
}


#ifndef __wasm__
#include <stdio.h>

int main()
{
    static char mem[1<<20];
    Arena a = {mem, 1[&mem]};
    uint64_t seed = (uintptr_t)mem;
    V2s vs = generate(seed, &a);
    for (ptrdiff_t i = 0; i < vs.len; i++) {
        printf("%ld,%ld\n", (long)vs.data[i].x, (long)vs.data[i].y);
    }
}
#endif
