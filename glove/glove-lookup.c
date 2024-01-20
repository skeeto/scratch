// This is free and unencumbered software released into the public domain.
#include "glove.c"

#define new(a, t, n)  (t *)alloc(a, sizeof(t), n)

static b32 fullwrite(u8 *, i32);

typedef struct {
    byte *beg;
    byte *end;
} arena;

static byte *alloc(arena *a, size objsize, size count)
{
    u32 align = -((u32)objsize * (u32)count) & 7;
    return memset(a->end -= align + objsize*count, 0, objsize*count);
}

typedef struct {
    u8  buf[1<<16];
    i32 len;
    b32 err;
} u8buf;

static void flush(u8buf *b)
{
    if (!b->err && b->len) {
        b->err = !fullwrite(b->buf, b->len);
        b->len = 0;
    }
}

static void prints8(u8buf *b, s8 s)
{
    for (size off = 0; !b->err && off<s.len;) {
        i32 avail = (i32)countof(b->buf) - b->len;
        i32 count = s.len-off < avail ? (i32)(s.len-off) : avail;
        memcpy(b->buf+b->len, s.data+off, count);
        off += count;
        b->len += count;
        if (b->len == countof(b->buf)) {
            flush(b);
        }
    }
}

static void printi32(u8buf *b, i32 x)
{
    u8  buf[32];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    i32 t = x>0 ? -x : x;
    do {
        *--beg = '0' - (u8)(t%10);
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    prints8(b, s8span(beg, end));
}

// FIXME: loses precision on very small numbers
static void printf32(u8buf *b, f32 f)
{
    i32 prec = 100000;  // 5 decimals
    if (f < 0) {
        prints8(b, s8("-"));
        f = -f;
    }

    f += 0.5f / (f32)prec;  // round last decimal
    if (f >= (f32)((u32)-1>>1)) {  // out of range?
        prints8(b, s8("inf"));
    } else {
        i32 integral = (i32)f;
        i32 fractional = (i32)((f - (f32)integral)*(f32)prec);
        printi32(b, integral);
        prints8(b, s8("."));
        for (i32 i = prec/10; i > 1; i /= 10) {
            if (i > fractional) {
                prints8(b, s8("0"));
            }
        }
        printi32(b, fractional);
    }
}

static b32 run(i32 argc, s8 *argv, void *db, arena scratch)
{
    glove g;
    glove_load_db(&g, db);

    u8buf *stdout = new(&scratch, u8buf, 1);
    for (i32 i = 1; i < argc; i++) {
        prints8(stdout, argv[i]);
        f32 *embedding = glove_get_embedding(&g, (char *)argv[i].data);
        if (!embedding) {
            prints8(stdout, s8(" (nil)\n"));
            continue;
        }
        for (i32 i = 0; i < g.num_dims; i++) {
            prints8(stdout, s8(" "));
            printf32(stdout, embedding[i]);
        }
        prints8(stdout, s8("\n"));
    }
    flush(stdout);
    return stdout->err;
}

