// Advent of Code 2023 Day 15
// https://adventofcode.com/2023/day/15
// https://nrk.neocities.org/articles/aoc23
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <string.h>

#define assert(c)     while (!(c)) *(volatile int *)0 = 0
#define new(a, t, n)  (t *)alloc(a, sizeof(t)*n)

typedef struct {
    char *beg, *end;
} arena;

static void *alloc(arena *a, ptrdiff_t size)
{
    if (size > a->end-a->beg) {
        assert(!"out of memory");
    }
    return memset(a->end -= size, 0, size);
}

typedef struct {
    char     *data;
    ptrdiff_t len;
} str;

static int equals(str a, str b)
{
    return a.len==b.len && !memcmp(a.data, b.data, a.len);
}

static str span(char *beg, char *end)
{
    str r = {0};
    r.data = beg;
    r.len = end - beg;
    return r;
}

static int hash(str s)
{
    unsigned h = 0;
    for (ptrdiff_t i = 0; i < s.len; i++) {
        h = 17*(h + s.data[i]);
    }
    return h & 255;
}

static unsigned hash32(str s)
{
    unsigned long long x = 0;
    memcpy(&x, s.data, s.len>8?8:s.len);
    x *= 1111111111111111111u;
    return (unsigned)(x ^ x>>32);
}

typedef struct {
    str value;
    str input;  // unconsumed input
} token;

static token parse(str input)
{
    token r = {0};
    char *beg = input.data;
    char *end = input.data + input.len;
    char *cut = beg;
    for (; cut<end && *cut!=',' && *cut>' '; cut++);
    r.value = span(beg, cut);
    for (; cut<end && (*cut==',' || *cut<=' '); cut++);
    r.input = span(cut, end);
    return r;
}

static int alpha(char c)
{
    return (unsigned)c-'a' <= 'z';
}

static str getlabel(str s)
{
    for (; s.len && !alpha(s.data[s.len-1]); s.len--) {}
    return s;
}

static int getfocus(str s)
{
    assert(s.len);
    int c = s.data[s.len-1];
    assert(c=='-' || (unsigned)c-'1'<9);
    return c=='-' ? 0 : c-'0';
}

// Intrusive, circular, doubly-linked list
typedef struct link link;
struct link {
    link *prev;
    link *next;
};

static void initlist(link *ln)
{
    ln->next = ln->prev = ln;
}

static void remove(link *ln)
{
    ln->prev->next = ln->next;
    ln->next->prev = ln->prev;
}

static void prepend(link *ln, link *next)
{
    ln->prev = next->prev;
    ln->next = next;
    ln->next->prev = ln;
    ln->prev->next = ln;
}

typedef struct node node;
struct node {
    link  list;  // first field: trivial list->node conversion
    node *map[2];
    str   label;
    int   focus;
};

typedef struct {
    link  list;
    node *map;
} box;

static box *newboxes(arena *perm)
{
    box *boxes = new(perm, box, 256);
    for (int i = 0; i < 256; i++) {
        initlist(&boxes[i].list);
    }
    return boxes;
}

static void setfocus(box *b, str label, int focus, arena *perm)
{
    // Find the node via hash-map lookup
    node **n = &b->map;
    for (unsigned h = hash32(label);; h <<= 1) {
        if (!*n) {
            (*n) = new(perm, node, 1);
            (*n)->label = label;
            prepend(&(*n)->list, &b->list);
            break;
        } else if (equals((*n)->label, label)) {
            if (!(*n)->focus) {
                remove(&(*n)->list);
                prepend(&(*n)->list, &b->list);
            }
            break;
        }
        n = &(*n)->map[h>>31];
    }
    (*n)->focus = focus;
}

static char *encode(char *p, int x)
{
    *--p = '\n';
    do *--p = (char)(x%10) + '0';
    while (x /= 10);
    return p;
}

static str solve(str input, void *heap, ptrdiff_t cap)
{
    arena scratch = {0};
    scratch.beg = (char *)heap;
    scratch.end = scratch.beg + cap;

    box *boxes = newboxes(&scratch);

    int part1 = 0;
    token tok = {0};
    tok.input = input;
    while (tok.input.len) {
        tok = parse(tok.input);
        part1 += hash(tok.value);

        str label = getlabel(tok.value);
        int focus = getfocus(tok.value);
        box *b = boxes + hash(label);
        setfocus(b, label, focus, &scratch);
    }

    int part2 = 0;
    for (int i = 0; i < 256; i++) {
        int slot = 0;
        box *b = boxes + i;
        for (link *ln = b->list.next; ln != &b->list; ln = ln->next) {
            node *n = (node *)ln;
            slot += !!n->focus;
            part2 += (i+1) * slot * n->focus;
        }
    }

    char *end = new(&scratch, char, 64) + 64;
    char *beg = end;
    beg = encode(beg, part2);
    beg = encode(beg, part1);
    return span(beg, end);
}


#if defined(_WIN32)
// $ cc -nostartfiles -o aoc2023d15.exe aoc2023d15.c
// $ cl aoc2023d15.c /link /subsystem:console kernel32.lib libvcruntime.lib
#define W32(r) __declspec(dllimport) r __stdcall
W32(void)   ExitProcess(int);
W32(void *) GetStdHandle(int);
W32(int)    ReadFile(void *, void *, int, int *, void *);
W32(void *) VirtualAlloc(void *, size_t, int, int);
W32(int)    WriteFile(void *, void *, int, int *, void *);

void mainCRTStartup(void)
{
    int cap = 1<<28;
    char *buf = (char *)VirtualAlloc(0, cap, 0x3000, 4);
    void *stdin = GetStdHandle(-10);
    str input = {0};
    input.data = buf;
    while (input.len < cap) {
        char *dst = input.data + input.len;
        int unused = (int)(cap - input.len);
        int len;
        if (!ReadFile(stdin, dst, unused, &len, 0) || !len) {
            break;
        }
        input.len += len;
    }

    str output = solve(input, buf+input.len, cap-input.len);

    void *stdout = GetStdHandle(-11);
    int len;
    int err = !WriteFile(stdout, output.data, (int)output.len, &len, 0);
    ExitProcess(err);
}

#elif defined(__linux) && defined(__amd64)
// $ musl-gcc -static -nostartfiles -O -o aoc2023d15 aoc2023d15.c

static ptrdiff_t fullread(char *buf, ptrdiff_t cap)
{
    for (ptrdiff_t len = 0; len < cap;) {
        ptrdiff_t r;
        asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(0), "D"(0), "S"(buf+len), "d"(cap-len)
            : "rcx", "r11", "memory"
        );
        if (r < 1) {
            return len;
        }
        len += r;
    }
}

static _Bool fullwrite(char *buf, ptrdiff_t len)
{
    for (ptrdiff_t off = 0; off < len;) {
        ptrdiff_t r;
        asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(1), "D"(1), "S"(buf+off), "d"(len-off)
            : "rcx", "r11", "memory"
        );
        if (r < 1) {
            return 0;
        }
        off += r;
    }
    return 1;
}

__attribute((force_align_arg_pointer))
void _start(void)
{
    asm (".comm heap, 1<<28, 8");
    extern char heap[];
    ptrdiff_t cap = 1<<28;
    str input = {0};
    input.data = heap;
    input.len = fullread(input.data, cap);

    str output = solve(input, heap+input.len, cap-input.len);

    _Bool err = !fullwrite(output.data, output.len);
    asm volatile ("syscall" : : "a"(60), "D"(err));
}

#else
// $ cc -o solve aoc2023d15.c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int cap = 1<<28;
    char *heap = malloc(cap);

    str input = {0};
    input.data = heap;
    input.len = fread(input.data, 1, cap, stdin);

    str output = solve(input, heap+input.len, cap-input.len);

    return !fwrite(output.data, output.len, 1, stdout);
}
#endif


#if 0
// Generate inputs for AoC-2023-15 with similar attribute distributions
// Very quick and dirty, just to make some quick, reasonable tests.
#include <stdio.h>
#include <stdint.h>

static int randint(uint64_t *s, int lo, int hi)
{
    *s = *s*0x3243f6a8885a308d + 1;
    return (int)(*s >> 33)%(hi - lo) + lo;
}

static int hash(char *s, int len)
{
    unsigned h = 0;
    for (int i = 0; i < len; i++) {
        h = 17*(h + *s);
    }
    return h & 255;
}

int main(void)
{
    enum {
        NOPS = 4000,
    };
    static int lengths[20] = {2,2,2,2,2,2,3,3,3,3,3,3,3,4,4,4,4,5,5,6};

    // seed silver   gold
    //    1 509457 244361
    //    2 497221 225963
    //    3 514129 249433
    //    4 511481 280358
    uint64_t rng = 1;

    int marks = 0;
    int nlabels = 0;
    char labels[NOPS][8] = {0};
    unsigned seen[8] = {0};
    for (int overflow = 250; marks<256 || --overflow; nlabels++) {
        int len = lengths[randint(&rng, 0, 20)];
        for (int i = 0; i < len; i++) {
            labels[nlabels][i] = (char)randint(&rng, 'a', 'z'+1);
        }
        int h = hash(labels[nlabels], len);
        unsigned b = 1u << h &31;
        marks += !(seen[b>>5] & b);
        seen[b>>5] |= b;
    }

    for (int i = 0; i < NOPS; i++) {
        fputs(labels[randint(&rng, 0, nlabels)], stdout);
        int focus = randint(&rng, -8, 10);
        if (focus < 1) {
            putchar('-');
        } else {
            putchar('=');
            putchar('0' + focus);
        }
        putchar(',');
    }
    fflush(stdout);
    return ferror(stdout);
}
#endif
