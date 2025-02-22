// Brodnik array test and benchmark
// $ cc -std=c++23 -g3 -fsanitize=undefined -fsanitize-trap -o test brodnik.cpp
// $ cc -std=c++23 -O2 -o bench brodnik.cpp
//
// In an arena context, Brodnik arrays don't require resizing storage,
// and so don't leave dead memory behind in the arena. However, they
// have more expensive access and are not contiguous. Just how much
// savings do they provide? Compare to my usual "slice" approach, the
// benchmark indicates Brodnik arrays halve memory at a 15% access time
// penalty, plus other non-contiguity costs.
//
// Future directions: The first chunk doesn't need to be size 1, and
// could start at, say, 8. That might have some advantages, especially
// when hand-vectorizing loops over Brodnik arrays.
//
// Ref: https://sedgewick.io/wp-content/themes/sedgewick/papers/1999Optimal.pdf
// Ref: https://old.reddit.com/r/algorithms/comments/1iun9zm
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define affirm(c)   while (!(c)) __builtin_unreachable()

typedef int32_t     i32;
typedef uint32_t    u32;
typedef int64_t     i64;
typedef uint64_t    u64;
typedef double      f64;
typedef char        byte;
typedef ptrdiff_t   iz;
typedef size_t      uz;

struct Arena {
    byte *beg;
    byte *end;
};

template<typename T>
void *operator new(uz, T *p) { return p; }

template<typename T>
static T *alloc(Arena *a, iz count = 1)
{
    iz size = sizeof(T);
    iz pad  = -(uz)a->beg & (alignof(T) - 1);
    assert(count < (a->end - a->beg - pad)/size);
    T *r = (T *)(a->beg + pad);
    a->beg += pad + count*size;
    for (iz i = 0; i < count; i++) {
        new (r+i) T();
    }
    return r;
}

template<typename T>
struct Slice {
    T *data = 0;
    iz len  = 0;
    iz cap  = 0;

    T &operator[](iz i)
    {
        affirm(i>=0 && i<len);
        return data[i];
    }
};

template<typename T>
static Slice<T> make(Arena *a, iz len, iz cap)
{
    Slice<T> r = {};
    r.data = alloc<T>(a, cap);
    r.len = len;
    r.cap = cap;
    return r;
}

template<typename T>
static Slice<T> make(Arena *a, iz cap)
{
    return make<T>(a, cap, cap);
}

template<typename T>
static Slice<T> copy(Arena *a, Slice<T> s)
{
    Slice<T> r = {};
    r.len = r.cap = s.len;
    r.data = alloc<T>(a, r.len);
    for (iz i = 0; i < r.len; i++) {
        r[i] = s[i];
    }
    return r;
}

template<typename T>
static Slice<T> push(Arena *a, Slice<T> s, T v)
{
    if (s.cap == s.len) {
        if ((byte *)(s.data+s.len) != a->beg) {
            s = copy(a, s);
        }
        iz extend = s.cap ? s.cap : 8;
        alloc<T>(a, extend);
        s.cap += extend;
    }
    s[s.len++] = v;
    return s;
}

template<typename T>
struct Brodnik {
    Slice<T *>chunks;
    iz        len;

    T &operator[](iz i)
    {
        affirm(i>=0 && i<len);
        iz ci = 63 - __builtin_clzll(i + 1);
        iz ai = i - (1z<<ci) + 1;
        return chunks[ci][ai];
    }
};

template<typename T>
static Brodnik<T> push(Arena *a, Brodnik<T> b, T v)
{
    iz ci = 63 - __builtin_clzll(b.len + 1);
    #if 0
    if (!b.chunks.len) {
        b.chunks = make<T *>(a, 0, 16);  // commit more at start
    }
    #endif
    if (ci == b.chunks.len) {
        b.chunks = push(a, b.chunks, alloc<T>(a, 1z<<ci));
    }
    iz ai = b.len - (1z<<ci) + 1;
    b.chunks[ci][ai] = v;
    b.len++;
    return b;
}

static i64 rdtscp()
{
    uz hi, lo;
    asm volatile ("rdtscp" : "=d"(hi), "=a"(lo) :: "cx", "memory");
    return (i64)hi<<32 | lo;
}

static u32 rand32(u64 *rng)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return u32(*rng>>32);
}

template<typename T>
static void benchmark(char const *name, Arena scratch)
{
    iz  cap      = scratch.end - scratch.beg;
    i32 nruns    = 1<<8;
    i32 npush    = 1<<21;
    u64 rng      = 1;
    i64 besttime = u64(-1)>>1;
    f64 meansize = 0;
    for (i32 n = 0; n < nruns; n++) {
        Arena a = scratch;
        i64 time = -rdtscp();

        #if 1
        T arrays[256] = {};
        #else
        T *arrays = alloc<T>(&a, 256);  // much slower?!
        #endif

        // Populate
        for (i32 i = 0; i < npush; i++) {
            u32 r = rand32(&rng);
            i32 j = r >> 24;
            arrays[j] = push(&a, arrays[j], i32(r));
        }

        // Index
        u32 scan = 0;
        for (i32 j = 0; j < 256; j++) {
            iz len = arrays[j].len;
            for (iz i = len; i > 0; i--) {
                scan += arrays[j][i-1];
            }
        }
        asm("" :: "r"(scan) : "memory");

        time += rdtscp();
        besttime = besttime<time ? besttime : time;

        meansize += double(cap - (a.end - a.beg)) / nruns;
    }
    printf("%8s%9d%9.3gMB\n", name, (int)(besttime>>10), meansize/(1<<20));
}

int main()
{
    iz    cap = 1z<<28;
    byte *mem = (byte *)malloc(cap);
    Arena a   = {mem, mem+cap};

    {
        Arena scratch = a;
        Brodnik<i64> bvals = {};
        for (i64 i = 0; i < 1000000; i++) {
            bvals = push(&scratch, bvals, (i+1)*(i+1));
        }
        for (i64 i = 1000000; i > 0; i--) {
            affirm(bvals[i-1] == i*i);
        }
    }

    benchmark<Slice<i32>>("Slice", a);
    benchmark<Brodnik<i32>>("Brodnik", a);
}
