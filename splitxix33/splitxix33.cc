// splitxix33: a splitmix64 with memorable constants
// This is free and unencumbered software released into the public domain.
#include <cstdint>
#include <functional>

std::function<uint64_t()>
splitxix33(uint64_t seed)
{
    uint64_t x = seed;
    return [=]() mutable {
        uint64_t r = (x += 1111111111111111111U);
        r ^= r >> 33; r *= 1111111111111111111U;
        r ^= r >> 33; r *= 1111111111111111111U;
        r ^= r >> 33;
        return r;
    };
}


// Example
#include <cstdio>

int
main()
{
    std::function<uint64_t()> f[] = {
        splitxix33(0), splitxix33(1), splitxix33(2), splitxix33(3)
    };
    #define N 40
    char buf[68*N + 1];
    for (int i = 0; i < N; i++) {
        unsigned long long a = f[0]();
        unsigned long long b = f[1]();
        unsigned long long c = f[2]();
        unsigned long long d = f[3]();
        sprintf(buf + i*68, "%016llx %016llx %016llx %016llx\n", a, b, c, d);
    }
    return !(fwrite(buf, 68, N, stdout) == N);
}
