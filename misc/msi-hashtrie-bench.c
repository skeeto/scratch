// MSI vs. hashtrie benchmark
//
// Obviously MSI hash tables are faster, but by how much? What are the
// relative memory costs when MSI hash tables leave behind husks? Looks
// like they're about 2x faster debugging and 3x faster in production,
// and they use slightly less memory (64-bit) despite the husks. Adjust
// ARYEXP to trade off time/space in the hashtrie.
//
// GCC 13.2, i9-12900:
// opt which       time-64     mem-64  time-32     mem-32
// -O0 msi         1.118       374M    0.976775    229M
//     hashtrie-2  2.64876     387M    2.44021     193M
//     hashtrie-4  1.90065     453M    1.652       226M
//     hashtrie-8  1.5586      585M    1.38075     292M
// -O1 msi         0.483835       "    0.541426       "
//     hashtrie-2  2.58083        "    2.222          "
//     hashtrie-4  1.73707        "    1.54139        "
//     hashtrie-8  1.42217        "    1.3287         "
// -O2 msi         0.425151       "    0.545215       "
//     hashtrie-2  2.50416        "    2.16417        "
//     hashtrie-4  1.55907        "    1.43333        "
//     hashtrie-8  0.997688       "    1.22931        "
// -O3 msi         0.368938       "    0.534606       "
//     hashtrie-2  2.30036        "    2.10187        "
//     hashtrie-4  0.997416       "    1.44067        "
//     hashtrie-8  0.846151       "    1.20017        "
//
// Ref: https://nullprogram.com/blog/2022/08/08/  (MSI hash table)
// Ref: https://nullprogram.com/blog/2023/09/30/  (hashtrie)
// Ref: https://nullprogram.com/blog/2023/10/05/  (dynamic array)
// This is free and unencumbered software released into the public domain.
#include <stddef.h>

#define assert(c)        while (!(c)) __builtin_unreachable()
#define tassert(c)       while (!(c)) __builtin_trap()
#define breakpoint(c)    ((c) ? ({ asm volatile ("int3; nop"); }) : 0)
#define countof(a)       (size)(sizeof(a) / sizeof(*(a)))
#define new(a, t, n)     (t *)alloc(a, sizeof(t), n)
#define s8(s)            (s8){(u8 *)s, countof(s)-1}
#define memset(d, c, n)  __builtin_memset(d, c, n)
#define memcpy(d, s, n)  __builtin_memcpy(d, s, n)
#define memcmp(a, b, n)  __builtin_memcmp(a, b, n)
#define push(s, a) ({ \
    typeof(a) A = (a); \
    typeof(s) S = (s); \
    if (S->len >= S->cap) { \
        grow(A, S, sizeof(*S->data)); \
    } \
    S->data + S->len++; \
})

typedef unsigned char      u8;
typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef   signed long long i64;
typedef unsigned long long u64;
typedef          size_t    uptr;
typedef          ptrdiff_t size;
typedef          char      byte;

typedef struct {
    char *beg;
    char *end;
} arena;

__attribute((malloc, alloc_size(2, 3)))
static byte *alloc(arena *a, size objsize, size count)
{
    size alignment = sizeof(void *);
    size padding   = -((u32)objsize * (u32)count) & (alignment - 1);
    size available = a->end - a->beg - padding;
    if (count > available/objsize) {
        tassert(0);
    }
    return memset(a->end-=objsize*count + padding, 0, objsize*count);
}

static void grow(arena *a, void *slice, size objsize)
{
    struct {
        void *data;
        size  cap;
        size  len;
    } replica;
    memcpy(&replica, slice, sizeof(replica));
    assert(replica.cap >= 0);
    assert(replica.len >= 0);
    assert(replica.len <= replica.cap);

    replica.cap += !replica.cap;
    void *data = alloc(a, objsize*2, replica.cap);
    if (replica.len) memcpy(data, replica.data, objsize*replica.len);
    replica.data = data;
    replica.cap *= 2;

    memcpy(slice, &replica, sizeof(replica));
}

typedef struct {
    u8  *data;
    size len;
} s8;

static s8 s8span(u8 *beg, u8 *end)
{
    s8 s = {0};
    s.data = beg;
    s.len = end - beg;
    return s;
}

static u64 s8hash(s8 s)
{
    u64 h = 0x100;
    for (size i = 0; i < s.len; i++) {
        h ^= s.data[i];
        h *= 1111111111111111111u;
    }
    return h;
}

static b32 s8equals(s8 a, s8 b)
{
    return a.len==b.len && (!a.len || !memcmp(a.data, b.data, a.len));
}

static s8 s8clone(s8 s, arena *perm)
{
    s8 r = {0};
    r.data = new(perm, u8, s.len);
    r.len = s.len;
    if (s.len) memcpy(r.data, s.data, s.len);
    return r;
}

typedef struct {
    s8  *data;
    size cap;
    size len;
} s8s;

enum { ARYEXP=2 };
typedef struct map map;
struct map {
    map *child[1<<ARYEXP];
    i32  symbol;
};

typedef struct {
    s8s  symbols;
    map *names;
} ht_symtab;

static i32 ht_intern(ht_symtab *t, s8 name, arena *perm)
{
    map **m = &t->names;
    for (u64 h = s8hash(name); *m; h <<= ARYEXP) {
        if (s8equals(name, t->symbols.data[(*m)->symbol])) {
            return (*m)->symbol;
        }
        m = &(*m)->child[h>>(64 - ARYEXP)];
    }
    *m = new(perm, map, 1);
    assert((i32)t->symbols.len == t->symbols.len);
    i32 symbol = (*m)->symbol = (i32)t->symbols.len;
    *push(&t->symbols, perm) = s8clone(name, perm);
    return symbol;
}

static s8 ht_symname(ht_symtab *t, i32 symbol)
{
    return t->symbols.data[symbol];
}

typedef struct {
    s8s  symbols;
    i32 *table;
    i32  exp;
} msi_symtab;

typedef struct {
    u64 hash;
    u32 mask;
    u32 step;
} msi;

static msi msi_params(msi_symtab *t, s8 name)
{
    msi r = {0};
    r.hash = s8hash(name);
    r.mask = ((u32)1<<t->exp) - 1;
    r.step = (u32)(r.hash>>(64 - t->exp)) | 1;
    return r;
}

static i32 msi_intern(msi_symtab *t, s8 name, arena *perm)
{
    i32 capacity = (i32)1 << t->exp;
    if (t->symbols.len >= capacity/2) {
        t->exp += 2;
        t->table = new(perm, i32, (size)1<<t->exp);
        for (size symbol = 0; symbol < t->symbols.len; symbol++) {
            msi p = msi_params(t, t->symbols.data[symbol]);
            for (i32 i = (i32)p.hash;;) {
                i = (i + p.step) & p.mask;
                if (!t->table[i]) {
                    t->table[i] = (i32)symbol + 1;  // bias
                    break;
                }
            }
        }
    }

    msi p = msi_params(t, name);
    for (i32 i = (i32)p.hash;;) {
        i = (i + p.step) & p.mask;
        i32 si = t->table[i] - 1;  // unbias
        if (si < 0) {
            assert((i32)t->symbols.len == t->symbols.len);
            i32 symbol = (i32)t->symbols.len;
            t->table[i] = symbol + 1;  // bias
            *push(&t->symbols, perm) = s8clone(name, perm);
            return symbol;
        } else if (s8equals(t->symbols.data[si], name)) {
            return si;
        }
    }
}

static s8 msi_symname(msi_symtab *t, i32 symbol)
{
    return t->symbols.data[symbol];
}


// Benchmark crud
#include <stdlib.h>
#include <stdio.h>

static arena newarena(size cap)
{
    arena a = {0};
    a.beg = malloc(cap);
    a.end = a.beg + cap;
    memset(a.beg, 0xa5, cap);
    return a;
}

static i64 rdtscp(void)
{
    uptr hi, lo;
    asm volatile (
        "rdtscp"
        : "=d"(hi), "=a"(lo)
        :
        : "cx", "memory"
    );
    return (i64)hi<<32 | lo;
}

static void ht_test(arena scratch)
{
    ht_symtab *ht = new(&scratch, ht_symtab, 1);
    i32 hello = ht_intern(ht, s8("hello"), &scratch);
    i32 world = ht_intern(ht, s8("world"), &scratch);

    s8 hellos = ht_symname(ht, hello);
    s8 worlds = ht_symname(ht, world);

    tassert(hello == ht_intern(ht, s8("hello"), &scratch));
    tassert(world == ht_intern(ht, s8("world"), &scratch));

    tassert(s8equals(hellos, ht_symname(ht, hello)));
    tassert(s8equals(worlds, ht_symname(ht, world)));
}

static s8 randname(u8 *dst, u64 *rng)
{
    u64 r = *rng = *rng*0x3243f6a8885a308du + 1;
    dst[0] = (u8)((r >> 32)&63) + '!';
    dst[1] = (u8)((r >> 40)&63) + '!';
    dst[2] = (u8)((r >> 48)&63) + '!';
    dst[3] = (u8)((r >> 56)&63) + '!';
    return s8span(dst, dst+4);
}

static void msi_test(arena scratch)
{
    msi_symtab *msi = new(&scratch, msi_symtab, 1);
    i32 hello = msi_intern(msi, s8("hello"), &scratch);
    i32 world = msi_intern(msi, s8("world"), &scratch);

    s8 hellos = msi_symname(msi, hello);
    s8 worlds = msi_symname(msi, world);

    tassert(hello == msi_intern(msi, s8("hello"), &scratch));
    tassert(world == msi_intern(msi, s8("world"), &scratch));

    tassert(s8equals(hellos, msi_symname(msi, hello)));
    tassert(s8equals(worlds, msi_symname(msi, world)));
}

typedef struct {
    size memory;
    i64  time;
} benchmark;

static benchmark ht_bench(arena scratch, i32 count, u64 seed)
{
    benchmark r = {0};
    r.memory += scratch.end - scratch.beg;
    r.time   -= rdtscp();

    u64 rng = seed;
    ht_symtab *t = new(&scratch, ht_symtab, 1);
    for (i32 i = 0; i < count; i++) {
        u8 buf[8];
        s8 name = randname(buf, &rng);
        ht_intern(t, name, &scratch);
    }

    r.time   += rdtscp();
    r.memory -= scratch.end - scratch.beg;
    return r;
}

static benchmark msi_bench(arena scratch, i32 count, u64 seed)
{
    benchmark r = {0};
    r.memory += scratch.end - scratch.beg;
    r.time   -= rdtscp();

    u64 rng = seed;
    msi_symtab *t = new(&scratch, msi_symtab, 1);
    for (i32 i = 0; i < count; i++) {
        u8 buf[8];
        s8 name = randname(buf, &rng);
        msi_intern(t, name, &scratch);
    }

    r.time   += rdtscp();
    r.memory -= scratch.end - scratch.beg;
    return r;
}

static void printbench(char *name, benchmark b)
{
    printf("%-10s%-12g%tdM\n", name, (double)b.time/2.42e9, b.memory>>20);
}

int main(void)
{
    arena scratch = newarena(1<<30);
    ht_test(scratch);
    msi_test(scratch);

    u64 seed = 1;
    i32 count = 5000000;
    benchmark ht = ht_bench(scratch, count, seed);
    printbench("hashtrie", ht);
    benchmark msi = msi_bench(scratch, count, seed);
    printbench("msi", msi);
}
