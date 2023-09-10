// NRK-tree: treap-like randomized binary search tree (experiment)
// $ ./treap | dot -Tpng >vars.png
// Ref: https://lists.sr.ht/~skeeto/public-inbox/%3C20230902232504.hcihm5fdw6k7kejq%40gen2.localdomain%3E
// This is free and unencumbered software released into the public domain.

typedef __UINT8_TYPE__   u8;
typedef unsigned int     u32;
typedef   signed int     i32;
typedef   signed int     b32;
typedef __UINT64_TYPE__  u64;
typedef __UINTPTR_TYPE__ uptr;
typedef unsigned char    byte;
typedef __PTRDIFF_TYPE__ size;
typedef __SIZE_TYPE__    usize;

#define sizeof(x)   (size)sizeof(x)
#define alignof(x)  (size)_Alignof(x)
#define countof(a)  (sizeof(a) / sizeof(*(a)))
#define lengthof(s) (countof(s) - 1)
#define assert(c)   while (!(c)) __builtin_unreachable()

static b32 os_write(i32, u8 *, i32);

#define new(...)            new_(__VA_ARGS__, new4, new3, new2)(__VA_ARGS__)
#define new_(a,b,c,d,e,...) e
#define new2(a, t)          (t *)alloc(a, sizeof(t), alignof(t), 1, 0)
#define new3(a, t, n)       (t *)alloc(a, sizeof(t), alignof(t), n, 0)
#define new4(a, t, n, f)    (t *)alloc(a, sizeof(t), alignof(t), n, f)
#define outofmemory(a) ({ \
    arena *a_ = (a); \
    a_->oom = new(a_, uptr, 5, SOFTFAIL); \
    !a_->oom || __builtin_setjmp(a_->oom); \
})

typedef struct {
    byte *beg;
    byte *end;
    uptr *oom;
} arena;

enum { SOFTFAIL = 1<<0, NOINIT = 1<<1 };
__attribute((malloc, alloc_size(2, 4), alloc_align(3)))
static byte *alloc(arena *a, size objsize, size align, size count, i32 flags)
{
    size avail = a->end - a->beg;
    size padding = -(uptr)a->beg & (align - 1);
    if (count > (avail - padding)/objsize) {
        if (SOFTFAIL & flags) {
            return 0;
        }
        __builtin_longjmp(a->oom, 1);
    }
    size total = count*objsize;
    byte *p = a->beg + padding;
    if (!(flags & NOINIT)) {
        for (size i = 0; i < total; i++) {
            p[i] = 0;
        }
    }
    a->beg += padding + total;
    return p;
}

static arena newscratch(arena *a, size div)
{
    size cap = (a->end - a->beg)/div;
    arena scratch = {};
    scratch.beg = new(a, byte, cap, NOINIT);
    scratch.end = scratch.beg + cap;
    scratch.oom = a->oom;
    return scratch;
}

#define S(s) (s8){(u8 *)s, lengthof(s)}
typedef struct {
    u8  *buf;
    size len;
} s8;

static size s8cmp(s8 a, s8 b)
{
    size len = a.len<b.len ? a.len : b.len;
    for (size i = 0; i < len; i++) {
        size d = a.buf[i] - b.buf[i];
        if (d) {
            return d;
        }
    }
    return a.len - b.len;
}

static s8 s8span(u8 *beg, u8 *end)
{
    s8 s = {};
    s.buf = beg;
    s.len = end - beg;
    return s;
}

static s8 s8clone(arena *a, s8 s)
{
    s8 c = {};
    c.buf = new(a, u8, s.len, NOINIT);
    c.len = s.len;
    for (size i = 0; i < s.len; i++) {
        c.buf[i] = s.buf[i];
    }
    return c;
}

static uptr s8hash(s8 s)
{
    u64 h = 0x100;
    for (size i = 0; i < s.len; i++) {
        h ^= s.buf[i];
        h *= 1111111111111111111u;
    }
    return (h ^ h>>32) & (uptr)-1;
}

typedef struct var var;
struct var {
    var *next[4];
    s8   key;
    s8   value;
};

typedef struct {
    var *vars;
} env;

static var *lookup(env *e, s8 key, arena *a)
{
    var **v = &e->vars;
    for (uptr hash = s8hash(key); *v; hash *= 31) {
        if (!s8cmp((*v)->key, key)) {
            return *v;
        }
        v = (*v)->next + (hash >> (8*sizeof(hash) - 2));
    }

    if (a) {
        *v = new(a, var);
        (*v)->key = key;
    }
    return *v;
}

static s8 s8i32(arena *a, i32 x)
{
    u8 buf[16];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    i32 t = x<0 ? x : -x;
    do {
        *--beg = '0' - (u8)(t%10);
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    return s8clone(a, s8span(beg, end));
}

static u32 hash32(u32 x)
{
    x += 0x80000000u; x ^= x >> 16;
    x *= 0x21f0aaadu; x ^= x >> 15;
    x *= 0xd35a2d97u; x ^= x >> 15;
    return x;
}

typedef struct {
    byte *buf;
    i32   len;
    i32   cap;
    i32   fd;
    b32   err;
} bufout;

static bufout *newbufout(arena *a, i32 cap, i32 fd)
{
    bufout *o = new(a, bufout);
    o->buf    = new(a, u8, cap, NOINIT);
    o->cap    = cap;
    o->fd     = fd;
    return o;
}

static void flush(bufout *o)
{
    if (!o->err && o->len) {
        o->err = !os_write(o->fd, o->buf, o->len);
        o->len = 0;
    }
}

static void s8write(bufout *o, s8 s)
{
    u8 *beg = s.buf;
    u8 *end = s.buf + s.len;
    while (!o->err && beg<end) {
        i32 avail = o->cap - o->len;
        i32 count = avail<end-beg ? avail : (i32)(end-beg);
        u8 *dst = o->buf + o->len;
        for (size i = 0; i < count; i++) {
            dst[i] = beg[i];
        }
        beg += count;
        o->len += count;
        if (o->cap == o->len) {
            flush(o);
        }
    }
}

static void printgraph(bufout *o, var *v)
{
    for (size i = 0; i < countof(v->next); i++) {
        if (v && v->next[i]) {
            s8write(o, S("    "));
            s8write(o, v->key);
            s8write(o, S(" -> "));
            s8write(o, v->next[i]->key);
            s8write(o, S(";\n"));
            printgraph(o, v->next[i]);
        }
    }
}

static u32 run(arena heap)
{
    arena perm[1] = {heap};
    if (outofmemory(perm)) {
        u8 buf[32];
        bufout stderr[1] = {};
        stderr->buf = buf;
        stderr->cap = countof(buf);
        stderr->fd  = 2;
        s8write(stderr, S("out of memory\n"));
        flush(stderr);
        return 1;
    }
    arena scratch = newscratch(perm, 3);

    i32 nvars = 1<<9;
    env *globals = new(perm, env);

    for (i32 i = 0; i < nvars; i++) {
        s8 key = s8i32(perm, i);
        s8 val = s8i32(perm, hash32(i));
        lookup(globals, key, perm)->value = val;
    }

    {
        arena tmp[1] = {scratch};
        for (i32 i = nvars-1; i >= 0; i--) {
            s8 key  = s8i32(tmp, i);
            s8 want = s8i32(tmp, hash32(i));
            s8 got  = lookup(globals, key, 0)->value;
            assert(!s8cmp(want, got));
        }
    }

    bufout *stdout = newbufout(perm, 1<<12, 1);
    s8write(stdout, S("digraph {\n"));
    printgraph(stdout, globals->vars);
    s8write(stdout, S("}\n"));
    flush(stdout);
    return stdout->err;
}


#ifdef _WIN32
// $ cc -nostartfiles -fno-builtin -o treap treap.c
typedef struct {} *handle;

#define W32 __attribute((dllimport, stdcall))
W32 byte  *VirtualAlloc(byte *, usize, u32, u32);
W32 void   ExitProcess(u32) __attribute((noreturn));
W32 handle GetStdHandle(u32);
W32 b32    WriteFile(handle, u8 *, u32, u32 *, void *);

static b32 os_write(i32 fd, u8 *buf, i32 len)
{
    handle h = GetStdHandle(-10 - fd);
    u32 dummy;
    return WriteFile(h, buf, len, &dummy, 0);
}

void mainCRTStartup(void)
{
    size heapcap = 1<<28;
    arena heap = {};
    heap.beg = VirtualAlloc(0, heapcap, 0x3000, 4);
    if (!heap.beg) {
        heap.beg = heap.end = (byte *)64;  // non-null empty
    } else {
        heap.end = heap.beg + heapcap;
    }
    u32 r = run(heap);
    ExitProcess(r);
}


#else
// $ cc -o treap treap.c
#include <stdlib.h>
#include <unistd.h>

static b32 os_write(i32 fd, u8 *buf, i32 len)
{
    for (i32 off = 0; off < len;) {
        i32 r = write(fd, buf+off, len-off);
        if (r < 1) {
            return 0;
        }
        off += r;
    }
    return 1;
}

int main(void)
{
    size heapcap = 1<<28;
    arena heap = {};
    heap.beg = malloc(heapcap);
    if (!heap.beg) {
        heap.beg = heap.end = (byte *)64;  // non-null empty
    } else {
        heap.end = heap.beg + heapcap;
    }
    return run(heap);
}
#endif
