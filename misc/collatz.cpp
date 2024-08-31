// Longest Collatz sequences (within memory limits)
//   $ cc -O2 -o collatz collatz.cpp
//   $ ./collatz | tee results.txt
//
// A little experiment extending a dense array with a sparse hash trie.
// Columns: ordinal, seed, length, seen peak, unseen peak, memory used
//
// As a bonus, a small trick to link against UCRT in w64devkit:
//   $ cc -nostdlib -O2 -D__USE_MINGW_ANSI_STDIO=0 -Dmain=x -e _Z1xv
//        -o collatz.exe collatz.cpp -lucrt
// Produces a tidy, short import table:
//   $ peports collatz.exe
//   api-ms-win-crt-heap-l1-1-0.dll
//           0       malloc
//   api-ms-win-crt-stdio-l1-1-0.dll
//           0       __acrt_iob_func
//           0       __stdio_common_vfprintf
//           0       fflush
//   api-ms-win-crt-string-l1-1-0.dll
//           0       memset
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(c) while (!(c)) *(volatile int *)0 = 0

void *operator new(size_t, void *p) { return p; }

struct arena {
    char *beg;
    char *end;
};

template<typename T>
static T *newbeg(arena *a, ptrdiff_t count = 1)
{
    ptrdiff_t size = sizeof(T);
    ptrdiff_t pad  = -(uintptr_t)a->beg & (alignof(T) - 1);
    ASSERT(count < (a->end - a->beg - pad)/size);
    T *r = (T *)(a->beg + pad);
    a->beg += pad + size*count;
    for (ptrdiff_t i = 0; i < count; i++) {
        new (r+i) T();
    }
    return r;
}

template<typename T>
static T *newend(arena *a, ptrdiff_t count = 1)
{
    ptrdiff_t size = sizeof(T);
    ptrdiff_t pad  = (uintptr_t)a->end & (alignof(T) - 1);
    ASSERT(count < (a->end - a->beg - pad)/size);
    a->end -= pad + size*count;
    T *r = (T *)a->end;
    for (ptrdiff_t i = 0; i < count; i++) {
        new (r+i) T();
    }
    return r;
}

struct map {
    map    *child[2];
    int64_t key;
    int32_t len;
};

static map *upsert(map **m, int64_t key, arena *a)
{
    for (uint64_t h = key*1111111111111111111u; *m; h <<= 2) {
        if ((*m)->key == key) {
            return *m;
        }
        m = &(*m)->child[h>>63];
    }
    *m = newend<map>(a);
    (*m)->key = key;
    return *m;
}

template<typename T>
struct list {
    T        *data = 0;
    ptrdiff_t len  = 0;
    ptrdiff_t cap  = 0;

    T &operator[](ptrdiff_t i) { return data[i]; }
};

template<typename T>
static list<T> clone(arena *a, list<T> x)
{
    list<T> r = x;
    r.data = newbeg<T>(a, x.len);
    for (ptrdiff_t i = 0; i < x.len; i++) {
        r[i] = x[i];
    }
    return r;
}

template<typename T>
static list<T> push(arena *a, list<T> x, T v)
{
    if (x.len == x.cap) {
        if ((char *)(x.data+x.cap) != a->beg) {
            x = clone(a, x);
        }
        ptrdiff_t extend = x.cap ? x.cap : 1<<8;
        newbeg<T>(a, extend);
        x.cap += extend;
    }
    x[x.len++] = v;
    return x;
}

// The cache stores results densely in an array up to a threshold, above
// which it stores results sparsely using a hash trie.
struct cache {
    int64_t   high   = 1;
    map      *sparse = 0;
    int32_t  *dense;
    ptrdiff_t len;

    cache(arena *a, ptrdiff_t threshold)
    {
        ASSERT(threshold > 1);
        len = threshold;
        dense = newend<int32_t>(a, threshold);
        dense[1] = 1;
    }
};

static int32_t *lookup(cache *c, int64_t key, arena *a)
{
    if (key < c->len) {
        return c->dense + key;
    }
    return &upsert(&c->sparse, key, a)->len;
}

static int32_t collatz(cache *c, int64_t key, arena *a)
{
    char           *save = a->beg;
    int32_t        *len  = lookup(c, key, a);
    list<int32_t *> path = push(a, {}, len);

    for (int64_t n = key; !*len;) {
        if (n % 2) {
            ASSERT(n <= 0x7ffffffffffffffe/3);
            n = 3*n + 1;
        } else {
            n /= 2;
        }
        c->high = n>c->high ? n : c->high;
        len  = lookup(c, n, a);
        path = push(a, path, len);
    }

    int32_t current = *len;
    for (ptrdiff_t i = path.len-2; i >= 0; i--) {
        *path[i] = ++current;
    }

    a->beg = save;
    return *path[0];
}

int main()
{
    ptrdiff_t cap   = (ptrdiff_t)18<<30;
    char     *mem   = (char *)malloc(cap);
    arena     a     = {mem, mem+cap};
    cache     c     = {&a, (ptrdiff_t)1<<31};
    int32_t   count = 0;
    int32_t   best  = 1;
    int64_t   hole  = 2;

    // The next result after 670'617'279 is 9'780'657'630, but it's an
    // enormous leap and takes far more than 32G of memory to compute,
    // which is beyond my current workstation. The arena is just large
    // enough for this stopping point.
    for (int64_t i = 2; i <= 670'617'279; i++) {
        int32_t r = collatz(&c, i, &a);
        if (r > best) {
            best = r;
            for (;*lookup(&c, hole, &a); hole++) {}
            printf("%2d%14lld%10d%20lld%12lld%10tdM\n",
                   (int)++count, (long long)i, (int)best-1,
                   (long long)c.high, (long long)hole,
                   (cap - (a.end - a.beg))>>20);
            fflush(stdout);
        }
    }
    return 0;
}
