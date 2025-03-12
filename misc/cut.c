// String cut benchmark
//   $ cc -O2 -funroll-loops -o bench cut.c
//
// From the Go standard library:
//   strings.Cut(string, string) (string, string, bool)
//
// It's a powerful and useful function. I've been using it in C with a
// single byte separator because that's usually all I need, and it's
// simpler to implement than a substring search. For substring search, a
// Rabin-Karp rolling hash (see rabin-karp.c) is simple and effective.
// Some questions:
//
// 1. Is it good in a cut function?
// 2. Is it worth switching algorithms for a single byte?
// 3. Is it worth holding bookkeping between calls?
//
// I also grabbed my SWAR cut from rexxd, where it was highly effective.
// However, it performs poorly here. I suspect the unpredictable branch
// of its loop. In rexxd it's effective because the regular format of
// typical input is perfectly predictable.
//
// For (1), definitely yes. For (2), probably no. The one-byte cut is
// only ~1% faster, and is probably not worth the complexity. For (3),
// definitely no. It's 5% slower even in cases where it should be a lot
// better (long needles). Not sure what's going on here.
//
// Overall I'm happy with these results. The simplest approach, always
// use cuts(), trivial to build in terms of findstr(), is the best. The
// Cutter implementation is complicated, and the interface isn't great.
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define S(s)        (Str){(u8 *)s, sizeof(s)-1}
#define affirm(c)   while (!(c)) __builtin_unreachable()

typedef unsigned char   u8;
typedef int32_t         b32;
typedef int32_t         i32;
typedef int64_t         i64;
typedef uint64_t        u64;
typedef ptrdiff_t       iz;
typedef size_t          uz;

typedef struct {
    u8 *data;
    iz  len;
} Str;

static Str takehead(Str s, iz len)
{
    affirm(len <= s.len);
    s.len = len;
    return s;
}

static Str cuthead(Str s, iz len)
{
    affirm(len <= s.len);
    if (len) {
        s.data += len;
        s.len  -= len;
    }
    return s;
}

static b32 equals(Str a, Str b)
{
    if (a.len != b.len) {
        return 0;
    }
    for (iz i = 0; i < a.len; i++) {
        if (a.data[i] != b.data[i]) {
            return 0;
        }
    }
    return 1;
}

static b32 hashead(Str s, Str head)
{
    if (s.len < head.len) {
        return 0;
    }
    s = takehead(s, head.len);
    return equals(s, head);
}

// Returns the haystack length when the needle is not found.
static iz findstr(Str haystack, Str needle)
{
    enum { mult = 257 };

    u64 match = 0;
    for (iz i = 0; i < needle.len; i++) {
        match = mult*match + needle.data[i];
    }

    u64 f = 1;
    u64 x = mult;
    for (iz n = needle.len-1; n > 0; n /= 2) {
        f *= n&1 ? x : 1;
        x *= x;
    }

    u64 hash = 0;
    iz  i    = 0;
    for (; i<needle.len-1 && i<haystack.len; i++) {
        hash = mult*hash + haystack.data[i];
    }
    for (; i < haystack.len; i++) {
        hash = mult*hash + haystack.data[i];
        iz beg = i - needle.len + 1;
        Str tail = cuthead(haystack, beg);
        if (hash==match && hashead(tail, needle)) {
            return beg;
        }
        hash -= f * haystack.data[beg];
    }
    return haystack.len;
}

typedef struct {
    Str head;
    Str tail;
    b32 ok;
} Cut;

static Cut cut(Str s, u8 sep)
{
    iz cut = 0;
    for (; cut<s.len && s.data[cut]!=sep; cut++) {}
    Cut r = {0};
    r.ok   = cut < s.len;
    r.head = takehead(s, cut);
    r.tail = cuthead(s, cut+r.ok);
    return r;
}

static Cut cutswar(Str s, u8 sep)
{
    iz cut = 0;
    for (; s.len-cut >= 8; cut += 8) {
        u64 x;
        __builtin_memcpy(&x, s.data+cut, 8);
        x ^= 0x0101010101010101u * sep;
        x |= (x>>4) & 0x0f0f0f0f0f0f0f0f;
        x |= (x>>2) & 0x0303030303030303;
        x |= (x>>1);
        x &= 0x0101010101010101;
        if (x != 0x0101010101010101) {
            break;
        }
    }

    for (; cut<s.len && s.data[cut]!=sep; cut++) {}
    Cut r = {0};
    r.ok   = cut < s.len;
    r.head = takehead(s, cut);
    r.tail = cuthead(s, cut+r.ok);
    return r;
}

static Cut cuts(Str s, Str sep)
{
    iz  cut = findstr(s, sep);
    Cut r   = {0};
    r.ok    = cut < s.len;
    r.head  = takehead(s, cut);
    r.tail  = cuthead(s, cut);
    if (r.ok) {
        r.tail = cuthead(r.tail, sep.len);
    }
    return r;
}

typedef struct {
    u64 match;
    u64 hash;
    u64 factor;
    Str haystack;
    Str needle;
    iz  i;
} Cutter;

static Cutter newcutter(Str haystack, Str needle)
{
    enum { mult = 257 };
    Cutter c   = {0};
    c.factor   = 1;
    c.haystack = haystack;
    c.needle   = needle;

    for (iz i = 0; i < needle.len; i++) {
        c.match = mult*c.match + needle.data[i];
    }

    u64 x = mult;
    for (iz n = needle.len-1; n > 0; n /= 2) {
        c.factor *= n&1 ? x : 1;
        x *= x;
    }
    return c;
}

static Str nextcut(Cutter *c)
{
    enum { mult = 257 };
    Cutter t = *c;  // work from copy, avoid alias with u8
    iz     n = t.i;
    Str    r = cuthead(t.haystack, n);

    for (; t.i<t.needle.len-1 && t.i<t.haystack.len; t.i++) {
        t.hash = mult*t.hash + t.haystack.data[t.i];
    }

    for (b32 done = 0; t.i<t.haystack.len && !done; t.i++) {
        t.hash = mult*t.hash + t.haystack.data[t.i];
        iz beg = t.i - t.needle.len + 1;
        Str tail = cuthead(t.haystack, beg);
        if (t.hash==t.match && hashead(tail, t.needle)) {
            r = takehead(r, beg-n);
            done = 1;
        }
        t.hash -= t.factor * t.haystack.data[beg];
    }
    *c = t;
    return r;
}

static i64 rdtscp(void)
{
    uz hi, lo;
    asm volatile ("rdtscp" : "=d"(hi), "=a"(lo) :: "cx", "memory");
    return (i64)hi<<32 | lo;
}

static u64 rand64(u64 *rng)
{
    return (*rng = *rng*0x3243f6a8885a308d + 1);
}

static u8 randletter(u64 *rng, i32 n)
{
    static u8 alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    affirm(n>0 && n<=36);
    i32 i = (i32)(((rand64(rng)>>32) * n)>>32);
    return alphabet[i];
}

static void fill(Str buf, i32 n, u64 *rng)
{
    for (iz i = 0; i < buf.len; i++) {
        buf.data[i] = randletter(rng, n);
    }
}

int main(void)
{
    iz  cap = (iz)1<<23;
    u8 *mem = malloc(cap);
    Str buf = {mem, cap};

    u64 rng   = 1;
    i32 nruns = 1<<6;
    for (i32 len = 1; len < 12; len++) {
        i64 best;

        fill(buf, 36, &rng);

        Str sep = {(u8[32]){0}, len};
        fill(sep, 26, &rng);

        best = (u64)-1>>1;
        for (i32 n = 0; n < nruns; n++) {
            i64 time = -rdtscp();
            Cut c = cuts(buf, sep);
            i32 i = 0;
            for (; c.ok; i++) c = cut(c.tail, *sep.data);
            volatile i32 sink = i; (void)sink;
            time += rdtscp();
            best = best<time ? best : time;
        }
        printf("%-8s%3d%10d\n", "cuts", len, (i32)(best>>10));

        best = (u64)-1>>1;
        for (i32 n = 0; n < nruns; n++) {
            i64 time = -rdtscp();
            Cutter c = newcutter(buf, sep);
            i32 i = 0;
            for (; c.i < buf.len; i++) nextcut(&c);
            volatile i32 sink = i; (void)sink;
            time += rdtscp();
            best = best<time ? best : time;
        }
        printf("%-8s%3d%10d\n", "cutter", len, (i32)(best>>10));

        if (len > 1) continue;

        best = (u64)-1>>1;
        for (i32 n = 0; n < nruns; n++) {
            i64 time = -rdtscp();
            Cut c = cut(buf, *sep.data);
            i32 i = 0;
            for (; c.ok; i++) c = cut(c.tail, *sep.data);
            volatile i32 sink = i; (void)sink;
            time += rdtscp();
            best = best<time ? best : time;
        }
        printf("%-8s%3d%10d\n", "cut", len, (i32)(best>>10));

        best = (u64)-1>>1;
        for (i32 n = 0; n < nruns; n++) {
            i64 time = -rdtscp();
            Cut c = cut(buf, *sep.data);
            i32 i = 0;
            for (; c.ok; i++) c = cutswar(c.tail, *sep.data);
            volatile i32 sink = i; (void)sink;
            time += rdtscp();
            best = best<time ? best : time;
        }
        printf("%-8s%3d%10d\n", "cutswar", len, (i32)(best>>10));
    }
}
