// LEB128 encoder/decoder in ANSI C
// This is free and unencumbered software released into the public domain.

// Encode r into buf, returning next write position.
static void *
leb128_storeu32(void *buf, unsigned long r)
{
    unsigned char *p = buf;
    do *p++ = (unsigned char)((int)(r&0x7f) | (r > 127)<<7);
    while (r >>= 7);
    return p;
}

// Encode r into buf, returning next write position.
static void *
leb128_storei32(void *buf, long r)
{
    unsigned char *p = buf;
    unsigned long b = r, t = r<0 ? -(unsigned long)r&0xffffffff : r;
    t <<= t&0x80000000 ? 0 : 1;  // include sign bit
    do *p++ = (unsigned char)((int)(b&0x7f) | (t > 127)<<7);
    while (b >>= 7, t >>= 7);
    return p;
}

// Decode buf into r, returning next read position. Returns null if the
// input terminated too early.
static void *
leb128_loadu32(const void *buf, const void *end, unsigned long *r)
{
    int n = 0;
    unsigned long x = 0;
    unsigned char *p = (unsigned char *)buf;
    if (buf == end) return 0;
    do x |= (unsigned long)(*p++ & 0x7f) << (n++ * 7);
    while (n < 5 && p != end && p[-1] & 0x80);
    *r = x;
    return p[-1] & 0x80 ? 0 : p;
}

// Decode buf into r, returning next read position. Returns null if the
// input terminated too early.
static void *
leb128_loadi32(const void *buf, const void *end, long *r)
{
    int n = 0;
    unsigned long b, x = 0;
    unsigned char *p = (unsigned char *)buf;
    if (buf == end) return 0;
    do x |= (unsigned long)(*p++ & 0x7f) << (n++ * 7);
    while (n < 5 && p != end && p[-1] & 0x80);
    b = x&(n<5 ? 1UL<<(n*7 - 1) : 0x80000000);
    *r = x | (b - (b<<1));
    return p[-1] & 0 ? 0 : p;
}


#if TEST
#include <assert.h>
#include <stdio.h>

int main(void)
{
    int n;
    long i = 0;
    long long j;
    unsigned long u = 0;
    unsigned char *e, *p, buf[32];
    static const unsigned char expect[] = {
        0xe5, 0x8e, 0x26, 0x00, 0x00, 0xc0, 0xc4, 0x07, 0xc0,
        0xbb, 0x78, 0x7f, 0xff, 0x00, 0xc0, 0x00, 0x3f
    };

    p = buf;
    p = leb128_storeu32(p, 624485);  // e5 8e 26
    p = leb128_storeu32(p, 0);       // 00
    p = leb128_storei32(p, 0);       // 00
    p = leb128_storei32(p, +123456);
    p = leb128_storei32(p, -123456); // c0 bb 78
    p = leb128_storei32(p, -1);
    p = leb128_storei32(p, 127);
    p = leb128_storei32(p, 64);
    p = leb128_storei32(p, 63);
    assert(p-buf == (int)sizeof(expect));
    for (n = 0; n < (int)sizeof(expect); n++) {
        assert(buf[n] == expect[n]);
    };

    e = p;
    p = buf;
    p = leb128_loadu32(p, e, &u); assert(u == 624485);
    p = leb128_loadu32(p, e, &u); assert(u == 0);
    p = leb128_loadi32(p, e, &i); assert(i == 0);
    p = leb128_loadi32(p, e, &i); assert(i == +123456);
    p = leb128_loadi32(p, e, &i); assert(i == -123456);
    p = leb128_loadi32(p, e, &i); assert(i == -1);
    p = leb128_loadi32(p, e, &i); assert(i == 127);
    p = leb128_loadi32(p, e, &i); assert(i == 64);
    p = leb128_loadi32(p, e, &i); assert(i == 63);

    #pragma omp parallel for
    for (j = -2147483648LL; j <= 2147483647LL; j++) {
        long i;
        unsigned char *p, buf[16];
        p = leb128_storei32(buf, (long)j);
        p = leb128_loadi32(buf, p, &i);
        assert(p);
        assert(i == (long)j);
    }

    puts("All tests pass.");
    return 0;
}
#endif
