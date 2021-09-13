// splitxix33: a splitmix64 with memorable constants
// This is free and unencumbered software released into the public domain.
#include <stdint.h>

uint64_t
splitxix33(uint64_t s[1])
{
    uint64_t r = (*s += 1111111111111111111U);
    r ^= r >> 33;  r *= 1111111111111111111U;
    r ^= r >> 33;  r *= 1111111111111111111U;
    r ^= r >> 33;
    return r;
}


// Example
#include <stdio.h>

int
main(void)
{
    #define N 40
    char buf[68*N + 1];
    uint64_t s[4] = {0, 1, 2, 3};
    for (int i = 0; i < N; i++) {
        unsigned long long a = splitxix33(s+0);
        unsigned long long b = splitxix33(s+1);
        unsigned long long c = splitxix33(s+2);
        unsigned long long d = splitxix33(s+3);
        sprintf(buf + i*68, "%016llx %016llx %016llx %016llx\n", a, b, c, d);
    }
    return !(fwrite(buf, 68, N, stdout) == N);
}
