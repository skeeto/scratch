// Gale-Shapley algorithm
// $ cc -g3 -fsanitize=undefined -fsanitize-trap gale-shapley.c
// Ref: https://old.reddit.com/r/C_Programming/comments/1j6fxqd
// Ref: https://web.ece.ucsb.edu/~jrmarden/ewExternalFiles/lecture05-notes.pdf
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
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

typedef int16_t Idx;

typedef struct {
    Idx *data;
    Idx  len;
} Square;

static Idx *get(Square p, Idx i, Idx j)
{
    affirm(i>=0 && i<p.len);
    affirm(j>=0 && j<p.len);
    return p.data + ((ptrdiff_t)i*p.len + j);
}

static Square invert(Square s, Arena *a)
{
    Square r = s;
    r.data = new(a, (ptrdiff_t)r.len*r.len, Idx);
    for (Idx i = 0; i < r.len; i++) {
        for (Idx j = 0; j < r.len; j++) {
            Idx d = *get(s, i, j);
            *get(r, i, d-1) = j;
        }
    }
    return r;
}

static _Bool validate(Square s, Arena scratch)
{
    Idx *seen = new(&scratch, s.len, Idx);
    for (Idx i = 0; i < s.len; i++) {
        for (Idx j = 0; j < s.len; j++) {
            Idx v = *get(s, i, j);
            if (v<1 || v>s.len || seen[v-1]++ != i) {
                return 0;
            }
        }
    }
    return 1;
}

static Idx *gale_shapley(Square aprefs, Square bprefs, Arena *a)
{
    affirm(validate(aprefs, *a));
    affirm(validate(bprefs, *a));
    affirm(aprefs.len == bprefs.len);

    Idx  len   = aprefs.len;
    Idx *match = new(a, len, Idx);
    for (Idx i = 0; i < len; i++) {
        match[i] = -1;
    }

    // Bookkeeping / indexing
    Arena  scratch = *a;
    Square ainv    = invert(aprefs, &scratch);
    Idx   *next    = new(&scratch, len, Idx);
    Idx   *queue   = new(&scratch, len, Idx);
    Idx    head    = 0;
    Idx    tail    = 0;
    for (Idx i = 0; i < len; i++) {
        queue[i] = i;
    }

    for (Idx remaining = len; remaining;) {
        Idx who = queue[tail];  // pop
        tail = tail+1==len ? 0 : tail+1;

        Idx candidate = *get(ainv, who, next[who]++);
        if (match[candidate] < 0) {
            // No previous match, auto-accept
            match[candidate] = who;
            remaining--;
            continue;
        }

        Idx reject  = who;
        Idx rank    = *get(bprefs, candidate, who);
        Idx current = *get(bprefs, candidate, match[candidate]);
        if (rank < current) {
            // New match is better, swap
            reject = match[candidate];
            match[candidate] = who;
        }
        queue[head] = reject;  // push
        head = head+1==len ? 0 : head+1;
    }

    return match;
}

static Idx randint(uint64_t *rng, Idx max)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return (Idx)(((*rng>>32) * max)>>32);
}

static Square randprefs(Idx len, uint32_t seed, Arena *a)
{
    Square s = {0};
    s.len  = len;
    s.data = new(a, (ptrdiff_t)len*len, Idx);

    uint64_t rng = (uint64_t)len<<32 | seed;
    for (Idx i = 0; i < len; i++) {
        Idx *r = get(s, i, 0);
        for (Idx j = 0; j < len; j++) {
            r[j] = j + 1;
        }
        for (Idx j = len-1; j > 0; j--) {
            Idx k = randint(&rng, j+1);
            Idx t = r[k];
            r[k]  = r[j];
            r[j]  = t;
        }
    }

    return s;
}

int main(void)
{
    ptrdiff_t cap = (ptrdiff_t)1<<30;  // 1G for huge test/benchmark
    char     *mem = malloc(cap);

    {
        // From the referenced lecture
        Square women = {
            (Idx[]){
                1, 2, 3, 4,
                1, 2, 3, 4,
                3, 1, 2, 4,
                2, 3, 1, 4,
            }, 4,
        };
        Square men = {
            (Idx[]){
                3, 4, 1, 2,
                2, 3, 4, 1,
                1, 2, 3, 4,
                3, 4, 2, 1,
            }, 4,
        };

        Arena scratch = {mem, mem+cap};
        Idx *r = gale_shapley(women, men, &scratch);
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
        Idx    len     = 10000;
        Square aprefs  = randprefs(len, 1234, &scratch);
        Square bprefs  = randprefs(len, 5678, &scratch);
        Idx *r = gale_shapley(aprefs, bprefs, &scratch);
        #if 0
        for (Idx i = 0; i < len; i++) {
            printf("%d %d\n", i, r[i]);
        }
        #endif
        Idx *volatile sink = r; (void)sink;
    }
}
