#include <stddef.h>
#include <stdint.h>

// Basic definitions

#define affirm(c)       while (!(c)) __builtin_trap()
#define lenof(a)        (iz)(sizeof(a) / sizeof(*(a)))
#define maxof(t)        ((t)-1<1 ? (((t)1<<(sizeof(t)*8-2))-1)*2+1 : (t)-1)
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
#define U(s)            (Str16){s, lenof(s)-1}

typedef unsigned char   u8;
typedef int32_t         i32;
typedef uint16_t        u16;
typedef uint16_t        char16_t;
typedef char16_t        c16;
typedef ptrdiff_t       iz;
typedef size_t          uz;

// Platform API

typedef struct {
    u8 *beg;
    u8 *end;
} Arena;

typedef struct {
    c16 *data;
    iz   len;
} Str16;

typedef struct {
    i32 *pids;
    i32  len;
} Pids;

typedef struct Plt Plt;

static Str16 pidname(Plt *, Arena *, i32 pid);
static Pids  dirpids(Plt *, Arena *, c16 *path);
static Pids  filepids(Plt *, Arena *, c16 **paths, i32 npaths);
static i32   write16(Plt *, i32 fd, Str16);

// Application

static uz touz(iz x)
{
    affirm(x >= 0);
    return (uz)x;
}

static i32 trunc32(iz x)
{
    return x>maxof(i32) ? maxof(i32) : (i32)x;
}

static u8 *alloc(Arena *a, iz count, iz size, iz align)
{
    iz pad = (iz)-(uz)a->beg & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    u8 *r = a->beg + pad;
    a->beg += count * size;
    return __builtin_memset(r, 0, touz(count*size));
}

typedef struct {
    Plt *plt;
    i32  len;
    i32  fd;
    i32  err;
    c16  buf[1<<12];
} Output;

static Output *newoutput(Plt *plt, Arena *a, i32 fd)
{
    Output *b = new(a, 1, Output);
    b->plt = plt;
    b->fd = fd;
    return b;
}

static void flush(Output *b)
{
    if (!b->err && b->len) {
        b->err = !write16(b->plt, b->fd, (Str16){b->buf, b->len});
        b->len = 0;
    }
}

static void print(Output *b, Str16 s)
{
    for (iz off = 0; !b->err && off<s.len;) {
        i32 avail = (i32)lenof(b->buf) - b->len;
        i32 count = s.len-off < avail ? (i32)(s.len-off) : avail;
        iz  bytes = count * (iz)sizeof(c16);
        __builtin_memcpy(b->buf+b->len, s.data+off, touz(bytes));
        off += count;
        b->len += count;
        if (b->len == lenof(b->buf)) {
            flush(b);
        }
    }
}

static i32 app(Plt *plt, i32 argc, c16 **argv, u8 *mem, iz cap)
{
    Arena a = {mem, mem+cap};

    Output *out = newoutput(plt, &a, 1);

    print(out, U(u".\n"));

    Pids pids = dirpids(plt, &a, u".");
    for (i32 i = 0; i < pids.len; i++) {
        Arena scratch = a;
        Str16 name = pidname(plt, &scratch, pids.pids[i]);
        print(out, U(u"\t"));
        print(out, name);
        print(out, U(u"\n"));
    }

    print(out, U(u"culprit.exe\n"));

    c16 *paths[] = {u"culprit.exe"};
    pids = filepids(plt, &a, paths, lenof(paths));
    for (i32 i = 0; i < pids.len; i++) {
        Arena scratch = a;
        Str16 name = pidname(plt, &scratch, pids.pids[i]);
        print(out, U(u"\t"));
        print(out, name);
        print(out, U(u"\n"));
    }

    flush(out);
    return out->err;
}
