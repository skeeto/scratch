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

typedef struct {
    c16 *name;
    i32  isdir;
} DirEntry;

typedef struct {
    DirEntry *data;
    iz        len;
} DirList;

typedef struct { c16  **data; iz len, cap; } Paths;
typedef struct { i32 lo, hi; }               Range;
typedef struct { Range *data; iz len, cap; } Ranges;

typedef struct { c16 *path; i32 *pids; i32 npids; } Result;
typedef struct { Result *data; iz len, cap; }        Results;

typedef struct Plt Plt;

static Str16   pidname(Plt *, Arena *, i32 pid);
static Pids    dirpids(Plt *, Arena *, c16 *path);
static Pids    filepids(Plt *, Arena *, c16 **paths, i32 npaths);
static i32     write16(Plt *, i32 fd, Str16);
static DirList listdir(Plt *, Arena *, c16 *path);

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
    a->beg += pad + count * size;
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

static void *push_(Arena *a, void *data, iz *pcap, iz size)
{
    iz cap = *pcap;
    iz align = _Alignof(void *);
    if (!data || a->beg != (u8 *)data + cap*size) {
        u8 *copy = alloc(a, cap, size, align);
        if (data) __builtin_memcpy(copy, data, touz(cap*size));
        data = copy;
    }
    iz extend = cap ? cap : 4;
    alloc(a, extend, size, 1);
    *pcap = cap + extend;
    return data;
}

#define push(a, s) \
    ((s)->len == (s)->cap \
    ? (s)->data = (__typeof__((s)->data))push_((a), (s)->data, \
          &(s)->cap, (iz)sizeof(*(s)->data)), \
      (s)->data + (s)->len++ \
    : (s)->data + (s)->len++)

static Str16 fromcstr16(c16 *s)
{
    Str16 r = {s, 0};
    if (s) for (; s[r.len]; r.len++) {}
    return r;
}

static c16 *pathcat(Arena *a, c16 *dir, c16 *name)
{
    iz dlen = fromcstr16(dir).len;
    iz nlen = fromcstr16(name).len;
    iz sep  = dlen && dir[dlen-1] != '\\' && dir[dlen-1] != '/';
    c16 *r  = new(a, dlen + sep + nlen + 1, c16);
    __builtin_memcpy(r, dir, touz(dlen * (iz)sizeof(c16)));
    if (sep) r[dlen] = '\\';
    __builtin_memcpy(r + dlen + sep, name, touz(nlen * (iz)sizeof(c16)));
    return r;
}

static void printi(Output *b, i32 x)
{
    c16  buf[16];
    c16 *end = buf + lenof(buf);
    c16 *beg = end;
    i32  t   = x < 0 ? x : -x;
    do {
        *--beg = (c16)('0' - t%10);
    } while (t /= 10);
    if (x < 0) *--beg = '-';
    print(b, (Str16){beg, end - beg});
}

static i32 app(Plt *plt, i32 argc, c16 **argv, u8 *mem, iz cap)
{
    Arena perm    = {mem, mem + cap/2};
    Arena scratch = {mem + cap/2, mem + cap};

    Output  *out     = newoutput(plt, &perm, 1);
    Results  results = {0};
    Paths    files   = {0};
    Paths    dirs    = {0};

    // Phase 1: Walk directory trees, collect dirs and files
    for (i32 argi = 1; argi < argc; argi++) {
        c16 *arg = argv[argi];
        Arena temp = scratch;
        DirList dl = listdir(plt, &temp, arg);
        if (dl.len >= 0) {
            *push(&perm, &dirs) = arg;
        } else {
            *push(&perm, &files) = arg;
        }
    }

    // Stack-based directory traversal (no recursion)
    for (iz di = 0; di < dirs.len; di++) {
        c16 *dir = dirs.data[di];

        // Check directory for holding processes
        {
            Arena temp = scratch;
            Pids dp = dirpids(plt, &temp, dir);
            if (dp.len > 0) {
                Result *r = push(&perm, &results);
                r->path  = dir;
                r->pids  = new(&perm, dp.len, i32);
                r->npids = dp.len;
                __builtin_memcpy(r->pids, dp.pids,
                                 touz(dp.len * (iz)sizeof(i32)));
            }
        }

        // List directory entries
        Arena temp = scratch;
        DirList dl = listdir(plt, &temp, dir);
        for (iz i = 0; i < dl.len; i++) {
            c16 *full = pathcat(&perm, dir, dl.data[i].name);
            if (dl.data[i].isdir) {
                *push(&perm, &dirs) = full;
            } else {
                *push(&perm, &files) = full;
            }
        }
    }

    // Phase 2: Binary search with filepids
    if (files.len > 0) {
        Ranges ranges = {0};
        *push(&perm, &ranges) = (Range){0, trunc32(files.len)};

        while (ranges.len > 0) {
            Range rng = ranges.data[--ranges.len];
            if (rng.lo >= rng.hi) continue;

            Arena temp = scratch;
            Pids fp = filepids(plt, &temp,
                               files.data + rng.lo, rng.hi - rng.lo);
            if (fp.len == 0) continue;

            if (rng.hi - rng.lo == 1) {
                Result *r = push(&perm, &results);
                r->path  = files.data[rng.lo];
                r->pids  = new(&perm, fp.len, i32);
                r->npids = fp.len;
                __builtin_memcpy(r->pids, fp.pids,
                                 touz(fp.len * (iz)sizeof(i32)));
            } else {
                i32 mid = rng.lo + (rng.hi - rng.lo) / 2;
                *push(&perm, &ranges) = (Range){rng.lo, mid};
                *push(&perm, &ranges) = (Range){mid, rng.hi};
            }
        }
    }

    // Phase 3: Output results
    for (iz i = 0; i < results.len; i++) {
        Result *r = results.data + i;
        print(out, fromcstr16(r->path));
        print(out, U(u"\n"));
        for (i32 j = 0; j < r->npids; j++) {
            Arena temp = scratch;
            Str16 name = pidname(plt, &temp, r->pids[j]);
            print(out, U(u"\t["));
            printi(out, r->pids[j]);
            print(out, U(u"] "));
            print(out, name);
            print(out, U(u"\n"));
        }
    }

    flush(out);
    return out->err;
}
