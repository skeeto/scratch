#include <math.h>
#include <stdint.h>
#include <string.h>

void
hash22(float *x, float *y)
{
    uint32_t hi, lo;
    memcpy(&hi, x, sizeof(hi));
    memcpy(&lo, y, sizeof(lo));
    uint64_t v = ~((uint64_t)hi<<32 | lo);
    v *= 0xaddc7c7ef4e6ce37;
    v ^= v >> 32;
    v *= 0x9e6f287da60cbcad;
    v ^= v >> 32;
    *x = ldexpf(v>>32, -32);
    *y = ldexpf((uint32_t)v, -32);
}

#include <stdio.h>

int
main(void)
{
    float x = 3.1415927;
    float y = 1e+06;
    printf("%.9g %.9g\n", x, y);
    hash22(&x, &y);
    printf("%.9g %.9g\n", x, y);
}
