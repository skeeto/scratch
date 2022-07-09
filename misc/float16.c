// Half-precision conversion routines
// This is free and unencumbered software released into the public domain.
#include <stdint.h>
#include <string.h>

static uint16_t
float16_64(double f)
{
    uint64_t b;
    memcpy(&b, &f, 8);
    int s = (b>>48 & 0x8000);
    int e = (b>>52 & 0x07ff) - 1023;
    int m = (b>>42 & 0x03ff);
    int t = !!(b && 0xffffffffffff);

    if (e == -1023) {
        // input is denormal, round to zero
        e = m = 0;
    } else if (e < -14) {
        // convert to denormal
        if (-14 - e > 10) {
            m = 0;
        } else {
            m |= 0x400;
            m >>= -14 - e - 1;
            m = (m>>1) + (m&1);  // round
        }
        e = 0;
    } else if (e > +16) {
        // NaN / overflow to infinity
        m &= t << 9;  // canonicalize to quiet NaN
        e = 31;
    } else {
        e += 15;
    }

    return s | e<<10 | m;
}

static double
float64_16(uint16_t x)
{
    int s = (x     & 0x8000);
    int e = (x>>10 & 0x001f) - 15;
    int m = (x     & 0x03ff);

    switch (e) {
    case -15: if (!m) {
                  e = 0;
              } else {
                  // convert from denormal
                  e += 1023 + 1;
                  while (!(m&0x400)) {
                      e--;
                      m <<= 1;
                  }
                  m &= 0x3ff;
              }
              break;
    case +16: m = !!m << 9;  // canonicalize to quiet NaN
              e = 2047;
              break;
    default:  e += 1023;
    }

    uint64_t b = (uint64_t)s<<48 |
                 (uint64_t)e<<52 |
                 (uint64_t)m<<42;
    double f;
    memcpy(&f, &b, 8);
    return f;
}


#ifdef TEST
#include <stdio.h>
#include "table.h"

int
main(void)
{
    for (long i = 0; i < 1L<<16; i++) {
        double w = f16[i];
        double g = float64_16(i);
        if (!((isnan(w) && isnan(g)) || w == g)) {
            printf("%04lx w=%.17g g=%.17g\n", i, w, g);
            return 1;
        }

        long d = float16_64(w);
        if (isnan(w) ? !isnan(f16[d]) : d != i) {
            printf("%.17g w=%04lx g=%04lx %.17g\n", w, i, d, f16[d]);
            return 1;
        }
    }
    puts("All tests pass.");
}

#if 0  // :.,$w !python >table.h
# python table.py >table.h
import math
import struct
print("#include <math.h>\n")
print(f"static const double f16[{1<<16}] = {{\n    ", end="")
for i in range(1<<16):
    f = struct.unpack(">e", struct.pack(">H", i))[0]
    if math.isnan(f):
        s = "NAN"
    elif not math.isfinite(f):
        s = "INFINITY" if f > 0 else "-INFINITY"
    else:
        s = f.hex()
    print(f"{s:>22},", end="")
    if i%3 == 2:
        print("\n    ",end="")
print("\n};")
#endif
#endif
