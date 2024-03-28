// Find sets of characters that spell the most words
//   Reads a word list on standard input and prints the best character
//   sets on standard output with the number of matching words.
// Ref: https://old.reddit.com/r/commandline/comments/1bnehga
// This is free and unencumbered software released into the public domain.
#define assert(c)     while (!(c)) __builtin_unreachable()
#define countof(a)    (isize)(sizeof(a) / sizeof(*(a)))
#define new(a, t, n)  (t *)alloc(a, sizeof(t), _Alignof(t), n)
#define s(s)          (s8){(u8 *)s, countof(s)-1}

typedef unsigned char    u8;
typedef   signed int     b32;
typedef   signed int     i32;
typedef unsigned int     u32;
typedef          char    byte;
typedef __PTRDIFF_TYPE__ isize;
typedef __UINTPTR_TYPE__ uptr;

static byte *osalloc(isize cap);
static i32   osread(u8 *, i32);
static b32   oswrite(u8 *, i32);

typedef struct {
    char *beg;
    char *end;
} arena;

static byte *alloc(arena *a, isize size, isize align, isize count)
{
    isize pad = (uptr)a->end & (align - 1);
    assert(count <= (a->end - a->beg - pad)/size);  // out of mmemory
    return __builtin_memset(a->end -= size*count + pad, 0, size*count);
}

typedef struct {
    u8   *data;
    isize len;
} s8;

static s8 span(u8 *beg, u8 *end)
{
    assert(beg <= end);
    s8 r = {0};
    r.data = beg;
    r.len = end - beg;
    return r;
}

static s8 clone(s8 s, arena *perm)
{
    s8 r = {0};
    r.data = new(perm, u8, s.len);
    r.len = s.len;
    __builtin_memcpy(r.data, s.data, r.len);
    return r;
}

static u32 hash(s8 s)
{
    u32 h = 0x811c9dc5;
    for (isize i = 0; i < s.len; i++) {
        h ^= s.data[i];
        h *= 0x1000193u;
    }
    return h;
}

static b32 equals(s8 a, s8 b)
{
    assert(a.data);
    assert(a.len >= 0);
    assert(b.data);
    assert(b.len >= 0);
    return a.len==b.len && !__builtin_memcmp(a.data, b.data, a.len);
}

static b32 lower(u8 c)
{
    return c>='a' && c<='z';
}

static b32 valid(s8 word)
{
    for (isize i = 0; i < word.len; i++) {
        if (!lower(word.data[i])) {
            return 0;
        }
    }
    return 1;
}

static s8 makekey(s8 s, arena *perm)
{
    u8 hist[256] = {0};
    for (isize i = 0; i < s.len; i++) {
        hist[s.data[i]]++;
    }

    s8 r = {0};
    r.data = new(perm, u8, s.len);
    for (u8 c = 'a'; c <= 'z'; c++) {
        for (i32 n = hist[c]; n; n--) {
            r.data[r.len++] = c;
        }
    }
    return r;
}

static b32 whitespace(u8 c)
{
    return c=='\t' || c=='\n' || c=='\r' || c==' ';
}

static s8 trimfront(s8 s)
{
    u8 *beg = s.data;
    u8 *end = s.data + s.len;
    for (; beg<end && whitespace(*beg); beg++) { }
    return span(beg, end);
}

typedef struct {
    s8 token;
    s8 tail;
} token;

static token next(s8 s)
{
    token r = {0};
    s = trimfront(s);
    u8 *beg = s.data;
    u8 *end = s.data + s.len;
    u8 *cut = beg;
    for (; cut<end && !whitespace(*cut); cut++) {}
    r.token = span(beg, cut);
    r.tail  = span(cut, end);
    return r;
}

typedef struct map map;
struct map {
    map   *next;
    map   *child[4];
    s8     key;
    isize  count;
};

static map *insert(map **m, s8 key, arena *perm)
{
    for (u32 h = hash(key); *m; h <<= 2) {
        if (equals((*m)->key, key)) {
            (*m)->count++;
            return *m;
        }
        m = &(*m)->child[h>>30];
    }

    *m = new(perm, map, 1);
    (*m)->key = key;
    (*m)->count++;
    return *m;
}

static isize compare(map *a, map *b)
{
    isize d = b->count - a->count;
    if (d) return d;

    s8 ak = a->key;
    s8 bk = b->key;
    isize len = ak.len<bk.len ? ak.len : bk.len;
    for (isize i = 0; i < len; i++) {
        i32 d = ak.data[i] - bk.data[i];
        if (d) return d;
    }
    return ak.len - bk.len;
}

static map *sort(map *head)
{
    if (!head || !head->next) {
        return head;
    }

    isize len = 0;
    map *tail = head;
    map *last = head;
    for (map *m = head; m; m = m->next, len++) {
        if (len & 1) {
            last = tail;
            tail = tail->next;
        }
    }

    last->next = 0;
    head = sort(head);
    tail = sort(tail);

    map  *rhead = 0;
    map **rtail = &rhead;
    while (head && tail) {
        if (compare(head, tail) < 0) {
            *rtail = head;
            head = head->next;
        } else {
            *rtail = tail;
            tail = tail->next;
        }
        rtail = &(*rtail)->next;
    }
    *rtail = head ? head : tail;
    return rhead;
}

typedef struct {
    s8    chars;
    isize count;
} set;

typedef struct {
    set  *data;
    isize len;
} sets;

static sets findsets(s8 s, arena *perm, arena scratch)
{
    map  *seen = 0;
    map  *head = 0;
    map **tail = &head;
    sets r     = {0};

    token t = next(s);
    for (; t.token.len; t = next(t.tail)) {
        if (!valid(t.token)) continue;
        arena tentative = *perm;
        s8 key = makekey(t.token, &tentative);
        map *m = insert(&seen, key, &scratch);
        if (m->count == 1) {
            *perm = tentative;
            *tail = m;
            tail = &m->next;
            r.len++;
        }
    }

    r.data = new(perm, set, r.len);
    r.len = 0;
    for (map *m = sort(head); m; m = m->next, r.len++) {
        r.data[r.len].chars = m->key;
        r.data[r.len].count = m->count;
    }
    return r;
}

static i32 truncsize(isize size)
{
    i32 max = 0x7fffffff;
    return size>max ? max : (i32)size;
}

static s8 loadstdin(arena *perm)
{
    s8 r = {0};
    r.data = (u8 *)perm->beg;
    isize avail = perm->end - perm->beg;
    for (;;) {
        i32 len = osread(r.data+r.len, truncsize(avail-r.len));
        if (!len) {
            perm->beg += r.len;
            return r;
        }
        r.len += len;
    }
}

typedef struct {
    u8 *buf;
    i32 len;
    i32 cap;
    b32 err;
} u8buf;

static void flush(u8buf *b)
{
    if (!b->err && b->len) {
        b->err = !oswrite(b->buf, b->len);
        b->len = 0;
    }
}

static void print(u8buf *b, s8 s)
{
    for (isize off = 0; !b->err && off<s.len;) {
        i32 avail = b->cap - b->len;
        i32 count = avail<s.len-off ? avail : (i32)(s.len-off);
        __builtin_memcpy(b->buf+b->len, s.data+off, count);
        b->len += count;
        off += count;
        if (b->len == b->cap) {
            flush(b);
        }
    }
}

static void printsize(u8buf *b, isize x)
{
    u8  buf[32];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    do {
        *--beg = (u8)(x%10) + '0';
    } while (x /= 10);
    print(b, span(beg, end));
}

static i32 solve(void)
{
    isize cap = 1<<26;
    arena perm[1] = {0};
    perm->end = (perm->beg = osalloc(cap)) + cap;
    arena scratch = {0};
    scratch.end = (scratch.beg = osalloc(cap)) + cap;

    u8buf *stdout = new(perm, u8buf, 1);
    stdout->cap = 1<<14;
    stdout->buf = new(perm, u8, stdout->cap);

    sets r = findsets(loadstdin(perm), perm, scratch);

    isize width = 0;
    for (isize i = 0; i < r.len; i++) {
        isize len = r.data[i].chars.len;
        width = width>len ? width : len;
    }

    for (isize i = 0; i < r.len; i++) {
        print(stdout, r.data[i].chars);
        for (isize j = r.data[i].chars.len; j <= width; j++) {
            print(stdout, s(" "));
        }
        printsize(stdout, r.data[i].count);
        print(stdout, s("\n"));
    }

    flush(stdout);
    return stdout->err;
}


#if _WIN32
// $ gcc -nostartfiles -O -o charsets.exe charsets.c
// $ ./charsets <words

#define W32(r) __declspec(dllimport) r __stdcall
W32(void)   ExitProcess(i32);
W32(uptr)   GetStdHandle(i32);
W32(b32)    ReadFile(uptr, u8 *, i32, i32 *, uptr);
W32(byte *) VirtualAlloc(uptr, isize, i32, i32);
W32(b32)    WriteFile(uptr, u8 *, i32, i32 *, uptr);

static byte *osalloc(isize cap)
{
    return VirtualAlloc(0, cap, 0x3000, 4);
}

static i32 osread(u8 *buf, i32 len)
{
    uptr stdin = GetStdHandle(-10);
    ReadFile(stdin, buf, len, &len, 0);
    return len;
}

static b32 oswrite(u8 *buf, i32 len)
{
    uptr stdout = GetStdHandle(-11);
    return WriteFile(stdout, buf, len, &len, 0);
}

__attribute((force_align_arg_pointer))
void mainCRTStartup(void)
{
    i32 r = solve();
    ExitProcess(r);
}

#elif __linux && __amd64
// $ musl-gcc -static -nostartfiles -O -o charsets charsets.c
// $ ./charsets </usr/share/dict/words

enum {
    SYS_read  = 0,
    SYS_write = 1,
    SYS_brk   = 12,
    SYS_exit  = 60,
};

static byte *osalloc(isize cap)
{
    uptr addr = 0;
    for (i32 i = 0; i < 2; i++) {
        asm volatile (
            "syscall"
            : "=a"(addr)
            : "a"(SYS_brk), "D"(i ? addr+cap : 0)
            : "rcx", "r11", "memory"
        );
    }
    return (byte *)(addr - cap);
}

static i32 osread(u8 *buf, i32 len)
{
    i32 r;
    asm volatile (
        "syscall"
        : "=a"(r)
        : "a"(SYS_read), "D"(0), "S"(buf), "d"(len)
        : "rcx", "r11", "memory"
    );
    return r < 0 ? 0 : r;
}

static b32 oswrite(u8 *buf, i32 len)
{
    for (i32 off = 0; off < len;) {
        i32 r;
        asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(SYS_write), "D"(1), "S"(buf+off), "d"(len-off)
            : "rcx", "r11", "memory"
        );
        if (r < 1) return 0;
        off += r;
    }
    return 1;
}

void entrypoint(void)
{
    i32 r = solve();
    asm ("syscall" :: "a"(SYS_exit), "D"(r));
    assert(0);
}

asm (
    "_start: .globl _start\n"
    "        call entrypoint\n"
);
#endif
