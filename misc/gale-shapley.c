// Gale-Shapley algorithm
// Ref: https://old.reddit.com/r/C_Programming/comments/1j6fxqd
// Ref: https://web.ece.ucsb.edu/~jrmarden/ewExternalFiles/lecture05-notes.pdf
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Infrastructure
#define affirm(c)       while (!(c)) __builtin_unreachable()
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
typedef struct { char *beg, *end; } Arena;
static char *alloc(Arena *a, ptrdiff_t count, ptrdiff_t size, ptrdiff_t align)
{
    ptrdiff_t pad = (uintptr_t)a->end & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    return memset(a->end -= pad + count*size, 0, count*size);
}

typedef struct {
    int *data;
    int  len;
} Square;

static int *get(Square p, int i, int j)
{
    affirm(i>=0 && i<p.len);
    affirm(j>=0 && j<p.len);
    return p.data + ((ptrdiff_t)i*p.len + j);
}

static Square invert(Square s, Arena *a)
{
    Square r = s;
    r.data = new(a, (ptrdiff_t)r.len*r.len, int);
    for (int i = 0; i < r.len; i++) {
        for (int j = 0; j < r.len; j++) {
            int d = *get(s, i, j);
            *get(r, i, d-1) = j;
        }
    }
    return r;
}

static _Bool validate(Square s, Arena scratch)
{
    int *seen = new(&scratch, s.len, int);
    for (int i = 0; i < s.len; i++) {
        for (int j = 0; j < s.len; j++) {
            int v = *get(s, i, j);
            if (v<1 || v>s.len || seen[v-1]++ != i) {
                return 0;
            }
        }
    }
    return 1;
}

static int *gale_shaply(Square aprefs, Square bprefs, Arena *a)
{
    affirm(validate(aprefs, *a));
    affirm(validate(bprefs, *a));
    affirm(aprefs.len == bprefs.len);

    int  len   = aprefs.len;
    int *match = new(a, len, int);
    for (int i = 0; i < len; i++) {
        match[i] = -1;
    }

    // Bookkeeping / indexing
    Arena  scratch = *a;
    Square ainv    = invert(aprefs, &scratch);
    int   *next    = new(&scratch, len, int);
    int   *queue   = new(&scratch, len, int);
    int    head    = 0;
    int    tail    = 0;
    for (int i = 0; i < len; i++) {
        queue[i] = i;
    }

    for (int remaining = len; remaining;) {
        int who = queue[tail];  // pop
        tail = tail+1==len ? 0 : tail+1;

        int candidate = *get(ainv, who, next[who]++);
        if (match[candidate] < 0) {
            // No previous match, auto-accept
            match[candidate] = who;
            remaining--;
            continue;
        }

        int reject  = who;
        int rank    = *get(bprefs, candidate, who);
        int current = *get(bprefs, candidate, match[candidate]);
        if (rank < current) {
            // Current match is better, swap
            reject = match[candidate];
            match[candidate] = who;
        }
        queue[head] = reject;  // push
        head = head+1==len ? 0 : head+1;
    }

    return match;
}

static int randint(unsigned long long *rng, int max)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return (int)(((*rng>>32) * max)>>32);
}

static Square randprefs(int len, int seed, Arena *a)
{
    Square s = {0};
    s.len  = len;
    s.data = new(a, (ptrdiff_t)len*len, int);

    unsigned long long rng = 0x100000000 | seed;
    for (int i = 0; i < len; i++) {
        int *r = get(s, i, 0);
        for (int j = 0; j < len; j++) {
            r[j] = j + 1;
        }
        for (int j = len-1; j > 0; j--) {
            int k = randint(&rng, j+1);
            int t = r[k];
            r[k]  = r[j];
            r[j]  = t;
        }
    }

    return s;
}

int main(void)
{
    ptrdiff_t cap = (ptrdiff_t)1<<33;  // 8G for huge test/benchmark
    char     *mem = malloc(cap);

    {
        // From the referenced lecture
        Square women = {
            (int[]){
                1, 2, 3, 4,
                1, 2, 3, 4,
                3, 1, 2, 4,
                2, 3, 1, 4,
            }, 4,
        };
        Square men = {
            (int[]){
                3, 4, 1, 2,
                2, 3, 4, 1,
                1, 2, 3, 4,
                3, 4, 2, 1,
            }, 4,
        };

        Arena scratch = {mem, mem+cap};
        int *r = gale_shaply(women, men, &scratch);
        for (int i = 0; i < 4; i++) {
            static char names[][4] = {
                "Ann", "Beth", "Cher", "Dot",
                "Al",  "Bob",  "Cal",  "Dan",
            };
            printf("%4.4s%5.4s\n", names[i], names[4+r[i]]);
        }
    }

    {
        // Test against a huge input
        Arena  scratch = {mem, mem+cap};
        int    len     = 10000;
        Square aprefs  = randprefs(len, 1234, &scratch);
        Square bprefs  = randprefs(len, 5678, &scratch);
        int *r = gale_shaply(aprefs, bprefs, &scratch);
        #if 0
        for (int i = 0; i < len; i++) {
            printf("%d %d\n", i, r[i]);
        }
        #endif
        int *volatile sink = r; (void)sink;
    }
}
