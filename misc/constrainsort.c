// Sort an array under constraints
// Ref: https://old.reddit.com/r/algorithms/comments/1ix38ym
// Ref: https://old.reddit.com/r/algorithms/comments/1ix38ym/_/mele2di/
// Ref: https://nullprogram.com/blog/2025/01/19/
// This is free and unencumbered software released into the public domain.
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t     u8;
typedef int32_t     b32;
typedef uint64_t    u64;
typedef ptrdiff_t   iz;
typedef char        byte;
#define lenof(a)    ((iz)(sizeof(a) / sizeof(*(a))))

#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
typedef struct { byte *beg, *end; } Arena;
static void *alloc(Arena *a, iz count, iz size, iz align)
{
    iz pad = (iz)a->end & (align - 1);
    assert(count < (a->end - a->beg - pad)/size);  // TODO: OOM policy
    return memset(a->end -= pad + size*count, 0, size*count);
}

#define S(s)    (Str){(u8 *)s, sizeof(s)-1}
typedef struct {
    u8 *data;
    iz  len;
} Str;

static u64 hash(Str s)
{
    u64 h = 0x100;
    for (iz i = 0; i < s.len; i++) {
        h ^= s.data[i];
        h *= 1111111111111111111u;
    }
    return h;
}

static b32 equals(Str a, Str b)
{
    return a.len==b.len && (!a.len || !memcmp(a.data, b.data, a.len));
}

typedef struct Map Map;
struct Map {
    Map *child[4];
    Str  key;
    iz   value;
};

static iz *upsert(Map **m, Str key, Arena *a)
{
    for (u64 h = hash(key); *m; h <<= 2) {
        if (equals(key, (*m)->key)) {
            return &(*m)->value;
        }
        m = &(*m)->child[h>>62];
    }
    if (!a) return 0;
    *m = new(a, 1, Map);
    (*m)->key = key;
    return &(*m)->value;
}

// Return constrained-sorted indices of ITEMS. Items in ORDER must
// appear in that order. Otherwise items retain their original order.
static iz *sort(Str *items, iz nitems, Str *order, iz norder, Arena *a)
{
    // Allocate return array
    iz   *result  = new(a, nitems, iz);
    Arena scratch = *a;  // discard remaining allocations

    // Construct an order index
    Map *ordermap = 0;
    for (iz i = 0; i < norder; i++) {
        *upsert(&ordermap, order[i], &scratch) = i;
    }

    // Partition
    iz *unordered  = new(&scratch, nitems, iz);
    iz  nunordered = 0;
    iz *offsets    = new(&scratch, norder, iz);  // for counting sort
    for (iz i = 0; i < nitems; i++) {
        iz *n = upsert(&ordermap, items[i], 0);
        if (n) {
            offsets[*n]++;
        } else {
            unordered[nunordered++] = i;
        }
    }
    for (iz i = 1; i < norder-1; i++) {
        offsets[i] += offsets[i-1];
    }
    for (iz i = norder-1; i > 0; i--) {
        offsets[i] = offsets[i-1];
    }
    offsets[0] = 0;

    // Counting sort
    iz  nordered = nitems - nunordered;
    iz *ordered  = new(&scratch, nordered, iz);
    for (iz i = 0; i < nitems; i++) {
        iz *n = upsert(&ordermap, items[i], 0);
        if (n) {
            ordered[offsets[*n]++] = i;
        }
    }

    // Merge
    iz oi  = 0;
    iz ui  = 0;
    iz len = 0;
    while (oi<nordered && ui<nunordered) {
        if (ordered[oi] < unordered[ui]) {
            result[len++] = ordered[oi++];
        } else {
            result[len++] = unordered[ui++];
        }
    }
    while (oi < nordered) {
        result[len++] = ordered[oi++];
    }
    while (ui < nunordered) {
        result[len++] = unordered[ui++];
    }
    return result;
}

int main(void)
{
    int   cap = 1<<21;
    byte *mem = malloc(cap);
    Arena a   = {mem, mem+cap};

    Str A=S("A"), B=S("B"), C=S("C"), D=S("D"), E=S("E");

    Str  items[] = {A, B, C, D, E};
    Str  order[] = {C, E, A};
    iz  *sorted  = sort(items, lenof(items), order, lenof(order), &a);

    fputs("[", stdout);
    for (int i = 0; i < lenof(items); i++) {
        if (i) fputs(", ", stdout);
        Str item = items[sorted[i]];
        fwrite(item.data, item.len, 1, stdout);
    }
    puts("]");
}
