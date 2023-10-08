// Markov Chain Text Generator
// $ cc -nostartfiles -fno-builtin -O2 -o markov.exe markov.c
// $ ./markov <corpus.txt
//
// Tokenizes standard input, assembles an NGRAM-gram Markov chain from
// the tokens, then generates NOUTPUTS outputs on standard output.
// 64-bit only. Demonstrates some newer techniques:
//
// * Nested hash-tries for the Markov chain. A new data structure I
// co-invented with NRK, designed to complement linear allocation.
// Overview: https://nrk.neocities.org/articles/hash-trees-and-tries
// This data structure is so simple that I knocked out the initial
// working version (no compressed pointers) from scratch in a half hour
// or so.
//
// * Compressed pointers for data structures allocated within the arena.
// This has two notable benefits. First, 64-bit hosts use only 32 bits
// for nearly all pointers, giving substantial memory savings. Second,
// the tree is relocatable, and so may be dumped out to storage and
// reloaded later. Well, sort of: It contains pointers into the input
// buffer, so that would still need to be mapped to the same address.
//
// Compressed pointers are represented by p32 integers and have a range
// of 8GiB in either direction. The extra range is because p32 is always
// 4-byte aligned and always points to a 4-byte aligned address, so the
// lowest 2 bits can be used for extending the range. It depends on the
// variety of tokens in the corpus, but an 8GiB tree supports ~640MiB of
// 3-gram reddit comments with light bot filtering. (Bots reduce variety
// and allow for larger inputs, but produce less interesting outputs. A
// huge portion of reddit comments are bots.)
//
// The p32load() and p32store() macros help, at the cost of some type
// safety, in decoding and encoding compressed pointers. A p32 must not
// be copied, but decoded then re-encoded in separate statements. All
// p32 objects must be allocated from the same arena, so do not create a
// local p32 variable. Instead, decode into a local pointer of the
// proper type, then re-encode into a p32 stored in the arena.
//
// Managing p32 pointers takes practice, and your compiler will not help
// you. Debugging in their presence is difficult. Proper tool support
// would substantially improve their practicality.
//
// This is free and unencumbered software released into the public domain.

typedef __UINT8_TYPE__   u8;
typedef   signed int     b32;
typedef   signed int     i32;
typedef   signed int     p32;
typedef unsigned int     u32;
typedef __INT64_TYPE__   i64;
typedef __UINT64_TYPE__  u64;
typedef char             byte;
typedef __PTRDIFF_TYPE__ size;
typedef __UINTPTR_TYPE__ uptr;
typedef __INTPTR_TYPE__  iptr;

#define sizeof(x)      (size)sizeof(x)
#define alignof(x)     (size)_Alignof(x)
#define countof(a)     (sizeof(a) / sizeof(*(a)))
#define lengthof(s)    (countof(s) - 1)
#define assert(c)      while (!(c)) __builtin_unreachable()
#define new(a, t, n)   (t *)alloc(a, sizeof(t), alignof(t), n)
#define p32store(i, p) *(i) = (p) ? (p32)(((uptr)(p) - (uptr)(i))>>2) : 0
#define p32load(i)     (*(i) ? (void *)((uptr)(i) + ((uptr)*(i)<<2)) : 0)

#define NGRAMS   3
#define NOUTPUTS 50

static b32  oswrite(i32, u8 *, i32);
static void osfail(void);

typedef struct {
    byte *beg;
    byte *end;
} arena;

__attribute((malloc, alloc_size(2, 4), alloc_align(3)))
static byte *alloc(arena *a, size objsize, size align, size count)
{
    size avail = a->end - a->beg;
    size padding = -(uptr)a->beg & (align - 1);
    if (count > (avail - padding)/objsize) {
        static const u8 msg[] = "out of memory\n";
        oswrite(2, (u8 *)msg, lengthof(msg));
        osfail();
    }
    size total = objsize*count;
    byte *r = a->beg + padding;
    for (size i = 0; i < total; i++) {
        r[i] = 0;
    }
    a->beg += padding + total;
    return r;
}

#define S(s) (s8){(u8 *)s, lengthof(s)}
typedef struct {
    u8  *buf;
    size len;
} s8;

static s8 s8span(u8 *beg, u8 *end)
{
    s8 s = {};
    s.buf = beg;
    s.len = end - beg;
    return s;
}

static u64 s8hash(s8 s)
{
    u64 h = 0x100;
    for (size i = 0; i < s.len; i++) {
        h ^= s.buf[i];
        h *= 1111111111111111111u;
    }
    return h ^ h>>32;
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

static b32 whitespace(u8 c)
{
    return c=='\t' || c=='\n' || c=='\r' || c==' ';
}

static b32 digit(u8 c)
{
    return c>='0' && c<='9';
}

static b32 upper(u8 c)
{
    return c>='A' && c<='Z';
}

static b32 letter(u8 c)
{
    return upper(c) || (c>='a' && c<='z');
}

static b32 punct(u8 c)
{
    return c=='!' || c=='"' || c=='#' || c=='$' || c=='%' || c=='&' ||
           c=='(' || c==')' || c=='*' || c=='+' || c==',' || c=='.' ||
           c=='/' || c==':' || c==';' || c=='<' || c=='=' || c=='>' ||
           c=='?' || c=='[' || c=='\\'|| c==']' || c=='^' || c=='`' ||
           c=='{' || c=='|' || c=='}' || c=='~';
}

typedef struct {
    s8  token;
    s8  input;
    b32 ok;
} token;

static token lex(s8 input)
{
    token r = {};

    u8 *beg = input.buf;
    u8 *end = beg + input.len;
    for (; beg<end && whitespace(*beg); beg++) {}

    if (beg == end) {
        return r;
    } else if (punct(*beg)) {
        r.token = s8span(beg, beg+1);
        r.input = s8span(beg+1, end);
        r.ok = 1;
        return r;
    } else {
        u8 *tok = beg;
        for (beg++; beg<end && !punct(*beg) && !whitespace(*beg); beg++) {}
        r.token = s8span(tok, beg);
        r.input = s8span(beg, end);
        r.ok = 1;
        return r;
    }
}

typedef struct {
    p32 child[4];  // hash-trie
    s8  word;
    p32 next;
    i32 count;
} counts;

static counts *countword(p32 *p, s8 word, arena *a)
{
    for (u64 h = s8hash(word); *p; h = h>>62 | h<<2) {
        counts *c = p32load(p);
        if (s8equal(c->word, word)) {
            c->count++;
            return 0;
        }
        p = &c->child[h>>62];
    }
    counts *c = new(a, counts, 1);
    c->word = word;
    c->count = 1;
    p32store(p, c);
    return c;
}

typedef struct {
    p32 child[4];  // hash-trie
    s8  words[NGRAMS];
    p32 counts;    // counts map
    p32 head;      // counts list
    i64 total;
} markov;

static markov *upsert(p32 *p, s8 *words, arena *a)
{
    u64 h = 0;
    for (i32 i = 0; i < NGRAMS; i++) {
        h ^= s8hash(words[i]);
        h *= 1111111111111111111u;
    }

    for (; *p; h = h>>62 | h<<2) {
        markov *m = p32load(p);
        b32 match = 1;
        for (i32 i = 0; i<NGRAMS && match; i++) {
            match &= s8equal(m->words[i], words[i]);
        }
        if (match) {
            return m;
        }
        p = &m->child[h>>62];
    }

    markov *m = 0;
    if (a) {
        m = new(a, markov, 1);
        for (i32 i = 0; i < NGRAMS; i++) {
            m->words[i] = words[i];
        }
        p32store(p, m);
    }
    return m;
}

typedef struct {
    u8 *buf;
    i32 len;
    i32 cap;
    i32 fd;
    b32 err;
} u8buf;

static void u8flush(u8buf *b)
{
    b->err |= b->fd == -1;
    if (!b->err && b->len) {
        b->err = !oswrite(b->fd, b->buf, b->len);
        b->len = 0;
    }
}

static u8buf *newu8buf(arena *a, i32 cap, i32 fd)
{
    u8buf *r = new(a, u8buf, 1);
    r->buf = new(a, u8, cap);
    r->cap = cap;
    r->fd  = fd;
    return r;
}

static void u8s8(u8buf *b, s8 s)
{
    u8 *beg = s.buf;
    u8 *end = s.buf + s.len;
    while (!b->err && beg<end) {
        i32 avail = b->cap - b->len;
        i32 count = avail<end-beg ? avail : (i32)(end-beg);
        u8 *dst = b->buf + b->len;
        for (i32 i = 0; i < count; i++) {
            dst[i] = beg[i];
        }
        beg += count;
        b->len += count;
        if (b->len == b->cap) {
            u8flush(b);
        }
    }
}

typedef struct {
    p32 markov;
    p32 next;
} start;

static b32 startword(s8 s)
{
    return upper(*s.buf);
}

static b32 endword(s8 s)
{
    u8 c = *s.buf;
    return s.len==1 && (c=='.' || c=='?' || c=='!');
}

static i64 rand40(u64 *s)
{
    *s = *s*0x3243f6a8885a308d + 1;
    return *s >> 40;
}

static u32 run(u64 rng, arena perm, s8 input)
{
    token t = {};
    t.input = input;

    s8 words[NGRAMS] = {};
    for (i32 i = 0; i < NGRAMS; i++) {
        t = lex(t.input);
        if (!t.ok) {
            return 1;
        }
        words[i] = t.token;
    }

    b32 lastend = 1;
    p32 *root = new(&perm, p32, 1);    // must be allocated in arena
    p32 *starts = new(&perm, p32, 1);  // must be allocated in arena
    while ((t = lex(t.input)).ok) {
        markov *m = upsert(root, words, &perm);
        m->total++;

        if (lastend && startword(words[0])) {
            start *s = new(&perm, start, 1);
            start *head = p32load(starts);
            p32store(&s->markov, m);
            p32store(&s->next, head);
            p32store(starts, s);
        }
        lastend = endword(words[0]);

        counts *c = countword(&m->counts, t.token, &perm);
        if (c) {
            counts *head = p32load(&m->head);
            p32store(&c->next, head);
            p32store(&m->head, c);
        }

        for (i32 i = 0; i < NGRAMS-1; i++) {
            words[i] = words[i+1];
        }
        words[NGRAMS-1] = t.token;
    }

    i64 nstarts = 0;
    for (start *s = p32load(starts); s; s = p32load(&s->next)) {
        markov *m = p32load(&s->markov);
        nstarts += m->total;
    }

    u8buf *stdout = newu8buf(&perm, 1<<12, 1);

    for (i32 i = 0; i < NOUTPUTS; i++) {
        i64 r = rand40(&rng) % nstarts;
        start *s = p32load(starts);
        for (;; s = p32load(&s->next)) {
            markov *m = p32load(&s->markov);
            if (r < m->total) {
                break;
            }
            r -= m->total;
        }
        markov *m = p32load(&s->markov);

        for (i32 i = 0; i < NGRAMS; i++) {
            words[i] = m->words[i];
            if (i && !punct(*words[i].buf)) {
                u8s8(stdout, S(" "));
            }
            u8s8(stdout, words[i]);
        }

        for (;;) {
            i64 n = rand40(&rng) % m->total;
            counts *c = p32load(&m->head);
            for (; n >= c->count; c = p32load(&c->next)) {
                n -= c->count;
            }
            if (!punct(*c->word.buf)) {
                u8s8(stdout, S(" "));
            }
            u8s8(stdout, c->word);
            if (endword(c->word)) {
                break;
            }

            for (i32 i = 0; i < NGRAMS-1; i++) {
                words[i] = words[i+1];
            }
            words[NGRAMS-1] = c->word;
            m = upsert(root, words, 0);
        }
        u8s8(stdout, S("\n"));
    }

    u8flush(stdout);
    return 0;
}


#ifdef _WIN32
#define W32 __attribute((dllimport, stdcall))
W32 void  ExitProcess(u32) __attribute((noreturn));
W32 i32   GetStdHandle(u32);
W32 b32   ReadFile(iptr, u8 *, u32, u32 *, void *);
W32 byte *VirtualAlloc(byte *, size, u32, u32);
W32 b32   WriteFile(iptr, u8 *, u32, u32 *, void *);

static b32 oswrite(i32 fd, u8 *buf, i32 len)
{
    i32 h = GetStdHandle(-10 - fd);
    u32 dummy;
    return WriteFile(h, buf, len, &dummy, 0);
}

static void osfail(void)
{
    ExitProcess(1);
}

static s8 loadstdin(void)
{
    s8 s = {};
    i32 stdin = GetStdHandle(-10);
    size cap = (size)(1<<29) + (size)(1<<27);  // 640MiB
    s.buf = VirtualAlloc(0, cap, 0x3000, 4);
    while (s.len < cap) {
        u32 len = (u32)(cap - s.len);
        if (!ReadFile(stdin, s.buf+s.len, len, &len, 0) || !len) {
            return s;
        }
        s.len += len;
    }
    return s;
}

__attribute((force_align_arg_pointer))
void mainCRTStartup(void)
{
    size cap = (size)1<<33;
    arena heap = {};
    heap.beg = VirtualAlloc(0, cap, 0x3000, 4);
    heap.end = heap.beg + cap;
    u64 rng;
    asm volatile ("rdrand %0" : "=r"(rng));
    u32 r = run(rng, heap, loadstdin());
    ExitProcess(r);
}
#endif
