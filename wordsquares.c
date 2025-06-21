// Word Square solver
//   $ cc -std=c23 -O2 -o wordsquares wordsquares.c
//   $ ./wordsquares <words 5 hello.....world
//   HELLO
//   AVOID
//   WORLD
//   SHALL
//   EENSY
//
// Input word list must be lexicographically sorted.
//
// Ref: https://old.reddit.com/r/C_Programming/comments/1lgfv5d
// Ref: https://github.com/trobicho/WordSquaresDLX
// Ref: https://www.youtube.com/watch?v=zWIsnrxL-Zc
// This is free and unencumbered software released into the public domain.
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define affirm(c)       while (!(c)) unreachable()
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))

static size_t tousize(ptrdiff_t n)
{
    affirm(n >= 0);
    return (size_t)n;
}

static ptrdiff_t fromusize(size_t n)
{
    affirm(n <= PTRDIFF_MAX);
    return (ptrdiff_t)n;
}

static char upper(char c)
{
    return c<'a'||c>'z' ? c : (char)(c+'A'-'a');
}

typedef struct {
    char *beg;
    char *end;
} Arena;

static void *alloc(Arena *a, ptrdiff_t count, ptrdiff_t size, ptrdiff_t align)
{
    ptrdiff_t pad = (ptrdiff_t)-(uintptr_t)a->beg & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    void *r = a->beg + pad;
    a->beg += pad + count*size;
    return memset(r, 0, tousize(count*size));
}

typedef struct {
    char     *data;
    ptrdiff_t len;
} Str;

static Str loadstdin(Arena *a)
{
    Str r   = {};
    r.data  = a->beg;
    r.len   = fromusize(fread(r.data, 1, tousize(a->end-a->beg), stdin));
    a->beg += r.len;
    return r;
}

typedef struct {
    char *words;
    int   nwords;
    int   size;
} Dict;

// Compact, normalize, and keep only properly-sized words.
static Dict compress(Str words, int size)
{
    affirm(words.len < INT_MAX);

    Dict d  = {};
    d.size  = size;
    d.words = words.data;

    int len = 0;
    for (ptrdiff_t i = 0; i < words.len; i++) {
        char c = upper(words.data[i]);
        if (c<'A' || c>'Z') {
            if (len == size) {
                d.nwords++;
            }
            len = 0;
        } else {
            d.words[(d.nwords*size)+len++] = c;
        }
    }

    return d;
}

static char *get(Dict d, int i)
{
    return d.words + i*d.size;
}

typedef struct {  // NOTE: half-open: [lo, hi)
    int lo;
    int hi;
} Interval;

static int findlo(Dict d, int lo, int hi, char *pre, int len)
{
    affirm(len <= d.size);
    while (lo <= hi) {
        int mid = (hi + lo) / 2;
        char *word = get(d, mid);
        int   cmp  = memcmp(pre, word, tousize(len));
        if (cmp < 1) {
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    return lo;
}

static int findhi(Dict d, int lo, int hi, char *pre, int len)
{
    affirm(len <= d.size);
    while (lo <= hi) {
        int mid = (hi + lo) / 2;
        char *word = get(d, mid);
        int   cmp  = memcmp(pre, word, tousize(len));
        if (cmp < 0) {
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    return hi + 1;
}

// Narrow the interval to the given prefix.
static Interval find(Dict d, Interval it, char *pre, int len)
{
    Interval r = {};
    r.lo = findlo(d, it.lo, it.hi-1, pre, len);
    r.hi = findhi(d, it.lo, it.hi-1, pre, len);
    return r;
}

static Interval all(Dict d)
{
    return (Interval){0, d.nwords};
}

typedef struct {
    Dict      dict;
    char     *grid;
    char     *word;
    Interval *rows;
    Interval *cols;
} Solver;

// Return a copy of the solver for local modification.
static Solver localize(Solver s, Arena *a)
{
    Solver r = s;

    r.grid = new(a, s.dict.size*s.dict.size, char);
    memcpy(r.grid, s.grid, tousize(s.dict.size*s.dict.size));

    r.rows = new(a, s.dict.size, Interval);
    for (int i = 0; i < s.dict.size; i++) {
        r.rows[i] = s.rows[i];
    }

    r.cols = new(a, s.dict.size, Interval);
    for (int i = 0; i < s.dict.size; i++) {
        r.cols[i] = s.cols[i];
    }

    return r;
}

static bool check(Solver s)
{
    for (int y = 0; y < s.dict.size; y++) {
        int len = 0;
        for (int x = 0; x < s.dict.size; x++) {
            char c = s.grid[y*s.dict.size + x];
            if (!c) break;
            s.word[len++] = c;
        }
        if (!len) continue;
        Interval it = find(s.dict, s.rows[y], s.word, len);
        if (it.hi-it.lo < 1) {
            return false;
        }
        s.rows[y] = it;  // narrow
    }

    for (int x = 0; x < s.dict.size; x++) {
        int len = 0;
        for (int y = 0; y < s.dict.size; y++) {
            char c = s.grid[y*s.dict.size + x];
            if (!c) break;
            s.word[len++] = c;
        }
        if (!len) continue;
        Interval it = find(s.dict, s.cols[x], s.word, len);
        if (it.hi-it.lo < 1) {
            return false;
        }
        s.cols[x] = it;  // narrow
    }

    return true;
}

static bool mirrored(Solver s)
{
    for (int i = 0; i < s.dict.size; i++) {
        if (s.grid[i] != s.grid[i*s.dict.size]) {
            return false;
        }
    }
    return true;
}

static void print(Solver s)
{
    for (int y = 0; y < s.dict.size; y++) {
        fwrite(s.grid + y*s.dict.size, 1, tousize(s.dict.size), stdout);
        putchar('\n');
    }
    putchar('\n');
    fflush(stdout);
}

static void solve_(Solver s, int i, Arena scratch)
{
    Dict d = s.dict;
    if (i == d.size*d.size) {
        if (!mirrored(s)) {
            print(s);
        }
    } else if (s.grid[i]) {
        solve_(s, i+1, scratch);
    } else {
        for (char c = 'A'; c <= 'Z'; c++) {
            Arena loop = scratch;
            Solver t = localize(s, &loop);
            t.grid[i] = c;
            if (check(t)) {
                solve_(t, i+1, loop);
            }
        }
    }
}

static void solve(Dict d, Arena scratch, char *template)
{
    Solver s = {};
    s.dict = d;
    s.grid = new(&scratch, d.size*d.size, char);
    if (template) {
        memcpy(s.grid, template, tousize(d.size*d.size));
    }
    s.word = new(&scratch, d.size, char);

    s.rows = new(&scratch, d.size, Interval);
    for (int i = 0; i < d.size; i++) {
        s.rows[i] = all(d);
    }

    s.cols = new(&scratch, d.size, Interval);
    for (int i = 0; i < d.size; i++) {
        s.cols[i] = all(d);
    }

    solve_(s, 0, scratch);
}

int main(int argc, char **argv)
{
    int   cap = 1<<24;
    char *mem = malloc(tousize(cap));
    Arena a   = {mem, mem+cap};

    int size = argc>1 ? atoi(argv[1]) : 4;
    if (size<1 || size>64) {
        return 1;
    }

    char *template = 0;
    if (argc > 2) {
        template = new(&a, size*size, char);
        for (int i = 0; i < size*size; i++) {
            char c = upper(argv[2][i]);
            if (!c) break;
            template[i] = c>='A'&&c<='Z' ? c : 0;
        }
    }

    Str  input = loadstdin(&a);
    Dict words = compress(input, size);

    printf("%d words\n\n", words.nwords);
    solve(words, a, template);
}
