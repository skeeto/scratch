// Longest numeric prefix between two arrays
//
// Given two numeric arrays 0 <= n < 1e9, find the longest common prefix
// length between pairs of elements from each. Example: 1230 and 12398
// have a common prefix of length 3 (123). Zero has no prefix.
//
// This source contains two solvers, one uses a 256MiB bit array as an
// integer set. The other is a base-10 trie. Neither aborts early (i.e.
// when the maximum has been reached) since the purpose is to benchmark
// the different approaches in general. In my runs, the trie is faster
// up to ~300k elements, and smaller up to ~1M (64-bit) or ~2M (32-bit)
// elements.
//
// Porting: Implement rdtscp()+memset(), pass 2GB heap to entrypoint(),
// write the returned buffer to standard output, then exit.
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <string.h>

#define countof(a)    (size)(sizeof(a) / sizeof(*(a)))
#define new(a, t, n)  (t *)alloc(a, sizeof(t)*(n))

typedef unsigned char      u8;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef   signed long long i64;
typedef unsigned long long u64;
typedef          char      byte;
typedef          ptrdiff_t size;
typedef          size_t    uptr;

static i64 rdtscp(void);

typedef struct {
    size memory;
    i32  best;
} solution;

typedef struct {
    byte *beg, *end;
} arena;

static byte *alloc(arena *a, size objsize)
{
    size available = a->end - a->beg;
    if (objsize > available) {
        *(volatile i32 *)0 = 0;  // need a larger heap!
    }
    return memset(a->end -= objsize, 0, objsize);
}

// Bit table solver

static void bitset(u32 *t, i32 i)
{
    t[i>>5] |= (u32)1 << (i & 31);
}

static u32 bitget(u32 *t, i32 i)
{
    return t[i>>5] & ((u32)1 << (i & 31));
}

static solution solve_table(i32 *a, i32 *b, size len, arena scratch)
{
    solution r = {0};
    r.memory = scratch.end - scratch.beg;

    u32 *table = new(&scratch, u32, 1<<26);
    for (size i = 0; i < len; i++) {
        for (i32 n = a[i]; n; n /= 10) {
            bitset(table, n);
        }
    }

    for (size i = 0; i < len; i++) {
        for (i32 n = b[i]; n; n /= 10) {
            if (bitget(table, n)) {
                i32 len = 1;
                for (; n /= 10; len++) {}
                r.best = len>r.best ? len : r.best;
                break;
            }
        }
    }

    r.memory -= scratch.end - scratch.beg;
    return r;
}

// Trie solver

typedef struct trie trie;
struct trie {
    trie *child[10];
};

static i32 insert(trie *t, i32 x, arena *perm)
{
    i32 unused = 0;
    i32 digits[10];
    for (; x; x /= 10) {
        digits[unused++] = (u8)(x % 10);
    }

    i32 len = 0;
    for (; unused; len++) {
        i32 digit = digits[--unused];
        if (!t->child[digit]) {
            if (!perm) return len;  // lookup only
            t->child[digit] = new(perm, trie, 1);
        }
        t = t->child[digit];
    }
    return len;
}

static solution solve_trie(i32 *a, i32 *b, size len, arena scratch)
{
    solution r = {0};
    r.memory = scratch.end - scratch.beg;

    trie *t = new(&scratch, trie, 1);
    for (size i = 0; i < len; i++) {
        insert(t, a[i], &scratch);
    }

    for (size i = 0; i < len; i++) {
        i32 n = insert(t, b[i], 0);
        r.best = n>r.best ? n : r.best;
    }

    r.memory -= scratch.end - scratch.beg;
    return r;
}

// Benchmark

static i32 randint(u64 *s)
{
    i32 r;
    do {
        *s = *s*0x3243f6a8885a308du + 1;
        r = (i32)(*s >> 34);
    } while (r > 999999999);
    return r;
}

typedef struct {
    i64      time;
    solution result;
    i32      len;
    u8       id;
} result;

static i32 power10(i32 e)
{
    i32 r = 1;
    for (; e; e--) r *= 10;
    return r;
}

static result *test(arena *perm)
{
    static const struct {
        solution (*f)(i32 *, i32 *, size, arena);
        u8 id;
    } solvers[] = {
        {solve_table, 'B'},
        {solve_trie,  'T'},
        // ... add new solvers freely ...
    };
    i32 nsolvers = countof(solvers);

    i32 nexp = 6;
    result *r = new(perm, result, nsolvers*nexp*5+1);

    u64 rng = 1;
    i32 testi = 0;
    for (i32 e = 1; e <= nexp; e++) {
        for (i32 scale = 1; scale < 10; scale += 2) {
            arena scratch = *perm;

            i32 len = scale*power10(e);
            i32 *a = new(&scratch, i32, len);
            i32 *b = new(&scratch, i32, len);

            for (size i = 0; i < len; i++) {
                a[i] = randint(&rng);
                b[i] = randint(&rng);
            }

            for (i32 i = 0; i < nsolvers; i++, testi++) {
                r[testi].id = solvers[i].id;
                r[testi].len = len;
                r[testi].time -= rdtscp();
                r[testi].result = solvers[i].f(a, b, len, scratch);
                r[testi].time += rdtscp();
            }
        }
    }

    return r;
}

typedef struct {
    u8 *buf;
    i32 len;
} u8buf;

static void writeu8(u8buf *b, u8 c)
{
    b->buf[b->len++] = c;
}

static void writei32(u8buf *b, i32 x, i32 w)
{
    u8 tmp[16], *p = tmp;
    do {
        *++p = '0' + (u8)(x%10);
    } while (x /= 10);
    for (i32 i = (i32)(p-tmp); i < w; i++) {
        writeu8(b, ' ');
    }
    while (p != tmp) {
        writeu8(b, *p--);
    }
}

static u8buf entrypoint(void *heap, size cap)
{
    arena perm[1] = {0};
    perm->end = (perm->beg = heap) + cap;
    memset(perm->beg, 0xa5, perm->end-perm->beg);  // commit whole arena
    result *r = test(perm);
    u8buf b = {0};
    b.buf = new(perm, u8, 1<<16);
    for (int i = 0; r[i].id; i++) {
        writeu8(&b, r[i].id);
        writei32(&b, r[i].len, 9);
        writei32(&b, r[i].result.best, 2);
        writei32(&b, (i32)(r[i].time>>20), 6);
        writei32(&b, (i32)(r[i].result.memory>>20), 5);
        writeu8(&b, 'M');
        writeu8(&b, '\n');
    }
    return b;
}

// Platform

#if defined(__i386) || defined(__amd64)
static i64 rdtscp(void)
{
    uptr hi, lo;
    asm volatile ("rdtscp" : "=d"(hi), "=a"(lo) : : "cx", "memory");
    return (i64)hi<<32 | lo;
}
#elif defined(_MSC_VER)
static i64 rdtscp(void)
{
    int aux;
    return __rdtscp(&aux);
}
#endif

#ifdef _WIN32
// $ gcc -O2 -nostartfiles numprefix.c
// $ clang -O2 -Wl,/subsystem:console numprefix.c -lkernel32 -lvcruntime
// $ cl /O2 numprefix.c /link /subsystem:console kernel32.lib libvcruntime.lib
#define W32(r) __declspec(dllimport) r __stdcall
W32(void *) VirtualAlloc(void *, size, i32, i32);
W32(i32)    GetStdHandle(i32);
W32(i32)    WriteFile(uptr, u8 *, i32, i32 *, uptr);
W32(void)   ExitProcess(i32);

void mainCRTStartup(void)
{
    // 32-bit gets 1GB, 64-bit gets 2GB
    size cap = (size)1<<(30 + (sizeof(size)==8));
    void *heap = VirtualAlloc(0, cap, 0x3000, 4);
    u8buf b = entrypoint(heap, cap);
    i32 stdout = GetStdHandle(-11);
    i32 err = !WriteFile(stdout, b.buf, b.len, &b.len, 0);
    ExitProcess(err);
}

#elif defined(__linux) && defined(__amd64)
// $ cc -static -nostdlib -O2 -fno-builtin numprefix.c
extern char heap[];
asm ("        .comm heap, 1<<31, 8\n"
     "        .globl _start\n"
     "_start: call start\n");

void *memset(void *d, int c, unsigned long len)
{
    for (unsigned long i = 0; i < len; i++) {
        ((char *)d)[i] = (char)c;
    }
    return d;
}

void start(void)
{
    u8buf b = entrypoint(heap, (size)1<<31);
    asm volatile (
        "syscall"
        : "=a"(b.len)
        : "a"(1), "D"(1), "S"(b.buf), "d"(b.len)
        : "rcx", "r11", "memory"
    );
    asm volatile ("syscall" : : "a"(60), "D"(b.len<1));
}
#endif
