// Random graph generator
// $ cc -O -o graphgen graphgen.c
// $ ./graph 25 11 | dot -Tsvg >graph.svg
// Ref: https://old.reddit.com/r/algorithms/comments/19edou7
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define assert(c)     while (!(c)) *(volatile int *)0 = 0
#define new(a, t, n)  (t *)alloc(a, sizeof(t), n)

typedef struct { char *beg, *end; } arena;

static void *alloc(arena *a, ptrdiff_t size, ptrdiff_t count)
{
    assert(count >= 0);
    ptrdiff_t align = -((unsigned)size*(unsigned)count) & (sizeof(void *) - 1);
    assert(count <= (a->end - a->beg - align)/size);
    return memset(a->end -= count*size + align, 0, count*size);
}

typedef struct { int32_t a, b; } edge;

static edge makedge(int32_t a, int32_t b)
{
    assert(a != b);
    edge e = {0};
    e.a = a<b ? a : b;
    e.b = a>b ? a : b;
    return e;
}

static _Bool match(edge x, edge y)
{
    return x.a==y.a && x.b==y.b;
}

typedef struct edgeset edgeset;
struct edgeset {
    edgeset *child[4];
    edge     key;
};

static uint64_t hash(edge e)
{
    uint64_t h = (uint64_t)e.a<<32 | (uint32_t)e.b;
    return h * 1111111111111111111u;
}

// Return true if key is not in the set, and add it if given an arena.
static _Bool insert(edgeset **s, edge key, arena *perm)
{
    for (uint64_t h = hash(key); *s; h <<= 2) {
        if (match((*s)->key, key)) {
            return 0;
        }
        s = &(*s)->child[h>>62];
    }
    if (perm) {
        (*s = new(perm, edgeset, 1))->key = key;
    }
    return 1;
}

typedef struct { uint64_t state; } rng;

static rng *newrng(arena *perm, uint64_t seed)
{
    rng *g = new(perm, rng, 1);
    g->state = seed + 1111111111111111111u;
    return g;
}

static void step(rng *s)
{
    s->state = s->state*0x3243f6a8885a308d + 1;
}

static int32_t rand32(rng *s, int32_t n)
{
    assert(n > 0);
    step(s);
    return (int32_t)(((s->state >> 32) * n) >> 32);
}

static int64_t rand64(rng *s, int64_t n)
{
    assert(n > 0);
    step(s);
    uint64_t x = s->state;
    x ^= x >> 32;
    x *= 1111111111111111111u;
    x ^= x >> 32;
    return (int64_t)(s->state >> 1) % n;
}

static void shuffle(int32_t *a, int32_t len, rng *g)
{
    for (int32_t i = len-1; i > 0; i--) {
        int32_t j = rand32(g, i+1);
        int32_t swap = a[i];
        a[i] = a[j];
        a[j] = swap;
    }
}

static int64_t getnedges(int32_t nverts, int32_t nedges)
{
    if (!nverts) {
        return 0;
    }
    return (int64_t)nverts - 1 + nedges;
}

static int64_t getmaxnedges(int32_t nverts)
{
    if (!nverts) {
        return 0;
    }
    return (int64_t)nverts*(nverts - 1)/2 - nverts + 1;
}

static edge randedge(int32_t nverts, rng *g)
{
    for (;;) {
        int32_t a = rand32(g, nverts);
        int32_t b = rand32(g, nverts);
        if (a != b) {
            return makedge(a, b);
        }
    }
}

// Randomly generate a connected graph with a given number of vertices
// and extra edges. The returned array has getnedges() elements. Returns
// null if too many edges were requested.
static edge *newgraph(int32_t nverts, int32_t nedges, rng *g, arena *perm)
{
    assert(nverts >= 0);
    assert(nedges >= 0);

    int64_t total64 = getnedges(nverts, nedges);
    if ((int32_t)total64!=total64 || nedges>getmaxnedges(nverts)) {
        return 0;  // too many edges requested
    }
    int32_t total = (int32_t)total64;

    edge *edges = new(perm, edge, total);
    arena scratch = *perm;

    // Construct a uniformly-random minimum spanning tree
    edgeset *set = 0;
    int32_t *verts = new(&scratch, int32_t, nverts);
    for (int32_t i = 0; i < nverts; i++) {
        verts[i] = i;
    }
    shuffle(verts, nverts, g);
    for (int32_t i = 1; i < nverts; i++) {
        int32_t a = verts[rand32(g, i)];
        int32_t b = verts[i];
        edge    e = edges[i-1] = makedge(a, b);
        insert(&set, e, &scratch);
    }

    if (!nverts) {
        return edges;  // nothing to do
    }

    // Check for enough memory for random sampling
    ptrdiff_t available = scratch.end - scratch.beg;
    ptrdiff_t nslots = available / (ptrdiff_t)sizeof(edgeset);
    _Bool lowmemory = nedges > nslots;

    int64_t maxedges = (int64_t)nverts * (nverts - 1) / 2;
    if (total > maxedges>>3 || lowmemory) {
        // Dense: use reservior sampling
        // Each possible edge is visited exactly once, so new edges do
        // not need to go into the set.
        int64_t i = 0;
        int32_t len = nverts-1;
        edge e = {0};
        for (e.a = 0; e.a < nverts-1; e.a++) {
            for (e.b = e.a+1; e.b < nverts; e.b++, i++) {
                if (len < total) {
                    edges[len] = e;
                    len += insert(&set, e, 0);
                } else {
                    int64_t j = rand64(g, i?i:1);
                    if (j<nedges && insert(&set, e, 0)) {
                        edges[nverts-1+j] = e;
                    }
                }
            }
        }

    } else {
        // Sparse: use random sampling
        for (int32_t i = 0; i < nedges; i++) {
            for (;;) {
                edge e = randedge(nverts, g);
                if (insert(&set, e, &scratch)) {
                    edges[nverts-1+i] = e;
                    break;
                }
            }
        }
    }

    return edges;
}

static uint64_t hashptr(void *p, uint64_t seed)
{
    seed ^= (uintptr_t)p;
    return seed *= 1111111111111111111u;
}

int main(int argc, char **argv)
{
    ptrdiff_t cap = (ptrdiff_t)1<<28;
    arena scratch = {0};
    scratch.end = (scratch.beg = malloc(cap)) + cap;

    uint64_t seed = 0;
    seed = hashptr(&seed, seed);
    seed = hashptr(scratch.end, seed);
    seed = hashptr(main, seed);
    rng *g = newrng(&scratch, seed);

    int32_t nverts = argc>1 ? atoi(argv[1]) : 7;
    int32_t nedges = argc>2 ? atoi(argv[2]) : 3;
    edge *edges = newgraph(nverts, nedges, g, &scratch);
    if (!edges) {
        long long max = getmaxnedges(nverts);
        fprintf(stderr, "%ld > %lld\n", (long)nedges, max);
        return 1;
    }
    int32_t total = (int32_t)getnedges(nverts, nedges);

    puts("graph {");
    puts("  node [shape=circle]");
    for (int32_t i = 0; i < total; i++) {
        printf("  %d -- %d\n", edges[i].a, edges[i].b);
    }
    puts("}");
}
