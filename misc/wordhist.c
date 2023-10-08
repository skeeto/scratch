// Word count histogram (hash-trie experiment, see treap.c)
// Windows: $ cc -nostartfiles -fno-builtin -o wordhist wordhist.c
//          $ cl /GS- wordhist.c /link /subsystem:console kernel32.lib
// Unix:    $ cc -o wordhist wordhist.c
// Usage:   $ ./wordhist <corpus.txt
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>

typedef uint8_t      u8;
typedef   signed int b32;
typedef   signed int i32;
typedef unsigned int u32;
typedef uint64_t     u64;
typedef uintptr_t    uptr;
typedef char         byte;
typedef ptrdiff_t    size;
typedef size_t       usize;

#define sizeof(x)    (size)sizeof(x)
#define alignof(x)   (size)_Alignof(x)
#define countof(a)   (sizeof(a)/sizeof(*(a)))
#define lengthof(s)  (countof(s) - 1)

static void osfail(void);
static i32  osread(i32, u8 *, i32);
static b32  oswrite(i32, u8 *, i32);

#define new(a, t, n) (t *)alloc(a, sizeof(t), alignof(t), n)

typedef struct {
    byte *beg;
    byte *end;
} arena;

static byte *alloc(arena *a, size objsize, size align, size count)
{
    size avail = a->end - a->beg;
    size padding = -(uptr)a->beg & (align - 1);
    if (count > (avail - padding)/objsize) {
        static const u8 msg[] = "out of memory\n";
        oswrite(2, (u8 *)msg, lengthof(msg));
        osfail();
    }
    size total = count * objsize;
    byte *p = a->beg + padding;
    a->beg += padding + total;
    for (size i = 0; i < total; i++) {
        p[i] = 0;
    }
    return p;
}

static void copy(u8 *restrict dst, u8 *restrict src, size len)
{
    for (size i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}

#define S(s) (s8){(u8 *)(s), lengthof(s)}
typedef struct {
    u8  *buf;
    size len;
} s8;

static s8 s8span(u8 *beg, u8 *end)
{
    s8 s = {0};
    s.buf = beg;
    s.len = end - beg;
    return s;
}

static b32 s8equal(s8 a, s8 b)
{
    if (a.len != b.len) {
        return 0;
    }
    for (size i = 0; i < a.len; i++) {
        if (a.buf[i] != b.buf[i]) {
            return 0;
        }
    }
    return 1;
}

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

static u32 s8hash(s8 s)
{
    u64 h = 0x100;
    for (size i = 0; i < s.len; i++) {
        h ^= s.buf[i];
        h *= 1111111111111111111u;
    }
    return (h ^ h>>32) & (u32)-1;
}

static s8 s8clone(arena *a, s8 s)
{
    s8 c = {0};
    c.buf = new(a, u8, s.len);
    c.len = s.len;
    copy(c.buf, s.buf, s.len);
    return c;
}

typedef struct seen seen;
struct seen {
    seen *next;
    seen *child[4];
    s8    word;
    size  count;
};

static seen *upsert(seen **s, s8 word, arena *a)
{
    for (u32 h = s8hash(word); *s; h *= 31u) {
        if (s8equal((*s)->word, word)) {
            return *s;
        }
        s = (*s)->child + (h >> 30);
    }
    *s = new(a, seen, 1);
    (*s)->word = s8clone(a, word);
    return *s;
}

static b32 u8isword(u8 b)
{
    static const u8 table[256] = {
        ['\t'] = 1, ['\n'] = 1, ['\r'] = 1, [' ' ] = 1, ['!' ] = 1,
        ['"' ] = 1, ['#' ] = 1, ['(' ] = 1, [')' ] = 1, ['*' ] = 1,
        ['+' ] = 1, [',' ] = 1, ['.' ] = 1, ['/' ] = 1, [':' ] = 1,
        [';' ] = 1, ['<' ] = 1, ['=' ] = 1, ['>' ] = 1, ['?' ] = 1,
        ['@' ] = 1, ['[' ] = 1, ['\\'] = 1, [']' ] = 1, ['^' ] = 1,
        ['`' ] = 1, ['{' ] = 1, ['|' ] = 1, ['}' ] = 1, ['~' ] = 1,
    };
    return !table[b];
}

typedef struct {
    seen *seen;
    seen *first;
    s8    word;
    size  cap;
} wordhist;

static void u8push(wordhist *wh, arena *a, u8 b)
{
    if (wh->cap == wh->word.len) {
        wh->cap = wh->cap ? wh->cap*2 : 64;
        u8 *word = new(a, u8, wh->cap);
        copy(word, wh->word.buf, wh->word.len);
        wh->word.buf = word;
    }
    wh->word.buf[wh->word.len++] = b;
}

static void finishword(wordhist *wh, arena *a)
{
    if (!wh->word.len) {
        return;
    }
    seen *node = upsert(&wh->seen, wh->word, a);
    if (!node->count) {
        node->next = wh->first;
        wh->first = node;
    }
    node->count++;
    wh->word.len = 0;
}

static void countwords(wordhist *wh, arena *a, u8 *buf, size len)
{
    if (!len) {
        finishword(wh, a);
    }
    for (size i = 0; i < len; i++) {
        u8 b = buf[i];
        if (u8isword(b)) {
            u8push(wh, a, b);
        } else {
            finishword(wh, a);
        }
    }
}

static b32 seencmp(seen *a, seen *b)
{
    if (a->count == b->count) {
        return s8cmp(a->word, b->word) < 0;
    } else {
        return b->count < a->count;
    }
}

static seen *merge(seen *a, seen *b)
{
    seen  *head = 0;
    seen **tail = &head;
    while (a && b) {
        if (seencmp(b, a)) {
            *tail = b;
            tail = &b->next;
            b = b->next;
        } else {
            *tail = a;
            tail = &a->next;
            a = a->next;
        }
    }
    *tail = a ? a : b;
    return head;
}

static seen *sort(seen *head, arena scratch)
{
    i32 len = 0;
    seen **list = new(&scratch, seen *, 64);
    size *depth = new(&scratch, size, 64);

    while (head) {
        list[len] = head;
        depth[len++] = 0;
        while (head->next && seencmp(head, head->next)) {
            head = head->next;
        }
        seen *last = head;
        head = head->next;
        last->next = 0;

        for (; len>1 && depth[len-1]==depth[len-2]; len--) {
            list[len-2] = merge(list[len-2], list[len-1]);
            depth[len-2]++;
        }
    }

    for (; len > 1; len--) {
        list[len-2] = merge(list[len-2], list[len-1]);
    }
    return len ? list[0] : 0;
}

typedef struct {
    u8 *buf;
    i32 len;
    i32 cap;
    b32 err;
} bufout;

static void flush(bufout *b)
{
    if (!b->err && b->len) {
        b->err = !oswrite(1, b->buf, b->len);
        b->len = 0;
    }
}

static void s8write(bufout *b, s8 s)
{
    u8 *buf = s.buf;
    u8 *end = s.buf + s.len;
    while (!b->err && buf<end) {
        i32 avail = b->cap - b->len;
        i32 count = avail<end-buf ? avail : (i32)(end-buf);
        copy(b->buf+b->len, buf, count);
        buf += count;
        b->len += count;
        if (b->len == b->cap) {
            flush(b);
        }
    }
}

static void print(bufout *b, size x)
{
    u8 buf[32];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    size t = x<0 ? x : -x;
    do {
        *--beg = '0' - (u8)(t%10);
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    s8write(b, s8span(beg, end));
}

static u32 wordhist_main(arena a)
{
    wordhist wh[1] = {0};
    i32 cap = 1<<12;
    u8 *buf = new(&a, u8, cap);

    for (i32 len = -1; len;) {
        len = osread(0, buf, cap);
        countwords(wh, &a, buf, len);
    }

    bufout stdout[1] = {0};
    stdout->cap = cap;
    stdout->buf = buf;
    for (seen *w = sort(wh->first, a); w; w = w->next) {
        print(stdout, w->count);
        s8write(stdout, S(" "));
        s8write(stdout, w->word);
        s8write(stdout, S("\n"));
    }
    flush(stdout);
    return stdout->err;
}


#ifdef _WIN32
typedef struct {int dummy;} *handle;

#define W32(r) __declspec(dllimport) r __stdcall
W32(byte *) VirtualAlloc(byte *, usize, u32, u32);
W32(handle) GetStdHandle(u32);
W32(b32)    ReadFile(handle, u8 *, u32, u32 *, void *);
W32(b32)    WriteFile(handle, u8 *, u32, u32 *, void *);
W32(void)   ExitProcess(u32);

static void osfail(void)
{
    ExitProcess(1);
}

static i32 osread(i32 fd, u8 *buf, i32 cap)
{
    handle stdin = GetStdHandle(-10 - fd);
    u32 len;
    ReadFile(stdin, buf, cap, &len, 0);
    return len;
}

static b32 oswrite(i32 fd, u8 *buf, i32 len)
{
    handle stdout = GetStdHandle(-10 - fd);
    u32 dummy;
    return WriteFile(stdout, buf, len, &dummy, 0);
}

void mainCRTStartup(void)
{
    enum { CAP = 1<<28 };
    arena a = {0};
    a.beg = VirtualAlloc(0, CAP, 0x3000, 4);
    a.end = a.beg + CAP;
    u32 r = wordhist_main(a);
    ExitProcess(r);
}

#else
#include <stdlib.h>
#include <unistd.h>

static void osfail(void)
{
    _exit(1);
}

static i32 osread(i32 fd, u8 *buf, i32 cap)
{
    return (i32)read(fd, buf, cap);
}

static b32 oswrite(i32 fd, u8 *buf, i32 len)
{
    for (i32 off = 0; off < len;) {
        i32 r = (i32)write(fd, buf+off, len-off);
        if (r < 1) {
            return 0;
        }
        off += r;
    }
    return 1;
}

int main(void)
{
    enum { CAP = 1<<28 };
    arena a = {0};
    a.beg = malloc(CAP);
    a.end = a.beg + CAP;
    return wordhist_main(a);
}
#endif
