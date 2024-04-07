// Extract symbols from "dumpbin /exports" on standard input
// $ cc -nostartfiles -o exports.exe exports.c
// $ cl exports.c /link /subsystem:console kernel32.lib libvcruntime.lib
// Ref: https://github.com/friendlyanon/simcity-noinstall (winmm-exports)
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <string.h>

#define assert(c)     while (!(c)) *(volatile int *)0 = 0
#define countof(a)    (isize)(sizeof(a) / sizeof(*(a)))
#define s(s)          (s8){(u8 *)s, countof(s)-1}
#define new(a, t, n)  (t *)alloc(a, sizeof(t), _Alignof(t), n)

typedef unsigned char u8;
typedef   signed int  b32;
typedef   signed int  i32;
typedef          char byte;
typedef ptrdiff_t     isize;
typedef size_t        uptr;

#define W32(r) __declspec(dllimport) r __stdcall
W32(void)   ExitProcess(i32);
W32(uptr)   GetStdHandle(i32);
W32(b32)    ReadFile(uptr, u8 *, i32, i32 *, uptr);
W32(byte *) VirtualAlloc(uptr, isize, i32, i32);
W32(b32)    WriteFile(uptr, u8 *, i32, i32 *, uptr);

typedef struct {
    byte *beg;
    byte *end;
} arena;

static byte *alloc(arena *a, isize size, isize align, isize count)
{
    isize pad = (uptr)a->end & (align - 1);
    assert(count <= (a->end - a->beg - pad)/size);
    return a->end -= size*count + pad;  // NOTE: assumes arena is zeroed
}

typedef struct {
    u8   *data;
    isize len;
} s8;

static s8 s8span(u8 *beg, u8 *end)
{
    assert(beg <= end);
    s8 r = {0};
    r.data = beg;
    r.len  = end - beg;
    return r;
}

static b32 s8equals(s8 a, s8 b)
{
    return a.len==b.len && !memcmp(a.data, b.data, a.len);
}

static b32 whitespace(u8 c)
{
    return c=='\t' || c=='\n' || c=='\r' || c==' ';
}

typedef struct {
    s8 head;
    s8 tail;
} cut;

static cut s8line(s8 s)
{
    u8 *beg = s.data;
    u8 *end = s.data + s.len;

    u8 *mid = beg;
    for (; mid<end && *mid!='\n'; mid++) {}
    mid += mid < end;  // include the newline

    cut r = {0};
    r.head = s8span(beg, mid);
    r.tail = s8span(mid, end);
    return r;
}

static cut s8field(s8 s)
{
    u8 *beg = s.data;
    u8 *end = s.data + s.len;
    for (; beg<end &&  whitespace(*beg); beg++) {}

    u8 *mid = beg;
    for (; mid<end && !whitespace(*mid); mid++) {}

    cut r = {0};
    r.head = s8span(beg, mid);
    r.tail = s8span(mid, end);
    return r;
}

typedef struct {
    u8 *buf;
    i32 len;
    i32 cap;
    b32 err;
} buf8;

static void flush(buf8 *b)
{
    if (b->err || !b->len) return;
    uptr stdout = GetStdHandle(-11);
    b->err = !WriteFile(stdout, b->buf, b->len, &b->len, 0);
    b->len = 0;
}

static void print(buf8 *b, s8 s)
{
    for (isize off = 0; !b->err && off<s.len;) {
        i32 avail = b->cap - b->len;
        i32 count = avail<s.len-off ? avail : (i32)(s.len-off);
        memcpy(b->buf+b->len, s.data+off, count);
        off += count;
        b->len += count;
        if (b->len == b->cap) {
            flush(b);
        }
    }
}

static i32 truncsize(isize n)
{
    i32 max = 0x7fffffff;
    return n>max ? max : (i32)n;
}

static s8 loadstdin(arena *perm)
{
    isize avail = perm->end - perm->beg;
    s8 r = {0};
    r.data = (u8 *)perm->beg;
    uptr stdin = GetStdHandle(-10);
    while (r.len < avail) {
        i32 len;
        ReadFile(stdin, r.data+r.len, truncsize(avail-r.len), &len, 0);
        if (len < 1) break;
        r.len += len;
    }
    // FIXME: if r.len==avail then input was truncated: treat as OOM
    return r;
}

void mainCRTStartup(void)
{
    isize cap = (isize)1<<26;
    arena scratch = {0};
    scratch.beg = VirtualAlloc(0, cap, 0x3000, 4);
    scratch.end = scratch.beg + cap;

    buf8 *out = new(&scratch, buf8, 1);
    out->cap = 1<<14;
    out->buf = new(&scratch, u8, out->cap);

    cut line = {0};
    line.tail = loadstdin(&scratch);

    for (b32 active = 0; line.tail.len;) {
        line = s8line(line.tail);

        cut field = {0};
        field.tail = line.head;
        field = s8field(field.tail);  // field 1
        field = s8field(field.tail);  // field 2
        field = s8field(field.tail);  // field 3

        if (active) {
            field = s8field(field.tail);  // field 4
            active = !!field.head.len;
            if (active) {
                print(out, field.head);
                print(out, s("\r\n"));
            }
        } else if (s8equals(field.head, s("RVA"))) {
            active = 1;
            line = s8line(line.tail);  // skip empty line
        }
    }

    flush(out);
    ExitProcess(out->err);
}
