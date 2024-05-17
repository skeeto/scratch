// Buddy Allocator (libc-free, GC-friendly querying)
//
// Standout features:
// * Internal pointers supported by all pointer-accepting interfaces
// * Aligned allocation (built atop internal pointers)
// * Safe queries on any pointer: non-owned pointers return blank data
// * Robust double-free detection (optional)
// * Low memory overhead (<1.6%), no allocation block prefixes
//
// With query interfaces supporting internal pointers, this allocator is
// a good foundation for a conservative garbage collector.
//
// This is free and unencumbered software released into the public domain.


// Interface

#include <stddef.h>

// Recommended as the primary allocation interface. Normal code should
// not operate on sizes.
#define heap_new(h, n, t)  (t *)heap_alloc3(h, n, sizeof(t), _Alignof(t))

enum {
    HEAP_MIN    = 2 + ((int)sizeof(void *)>>2),
    HEAP_DEBUG  = 1 << 0,
    HEAP_STRICT = 1 << 1,
};

typedef struct heap heap;

typedef struct {
    void     *base;
    ptrdiff_t size;
    int       exp;   // size class: size = (ptrdiff_t)1<<exp
} heap_block;

// Initialize a heap for allocating out of the given memory region. The
// region may have any alignment. The flags may be zero or more ORed
// HEAP_DEBUG or HEAP_STRICT. Returns null if the region is too small.
//
// When the HEAP_DEBUG flag is set, memory is pattern-filled on free,
// and double-frees are detected. These operations introduce a small
// performance cost to heap_free().
//
// When the HEAP_STRICT flag is set, internal pointers are unsupported
// by heap_free(), and attempts to use them will abort. This flag is
// incompatible with overly-aligned allocations. It does not speed up
// freeing.
//
// Slightly more than 1/64th of the region is used for bookkeeping, and
// the most efficiently-used regions will be about that much larger than
// a power of two. For instance, allocate a virtual memory of size:
//   (1<<N) + (1<<(N-6)) + page_size
//   heap     heapstate    misc.
static heap *heap_init(void *, ptrdiff_t, int flags);

// Allocate zero-initialized memory, like malloc(3). Returns null if the
// memory could not be allocated. Alignment is 1<<HEAP_MIN, or 8-byte on
// 32-bit and 16-byte on 64-bit. This is the lowest-level allocator and
// should generally be avoided as error-prone.
static void *heap_alloc1(heap *, ptrdiff_t size);

// Allocate zero-initialized memory, like calloc(3). Returns null if the
// memory could not be allocated. Alignment matches heap_alloc1().
static void *heap_alloc2(heap *, ptrdiff_t n, ptrdiff_t size);

// Allocate zero-initialized memory, like aligned_alloc(3). Returns null
// if the memory could not be allocated. Alignment must be a power of
// two, which excludes zero. Regardless of the request, the minimum
// alignment will be the same as heap_alloc1().
static void *heap_alloc3(heap *, ptrdiff_t n, ptrdiff_t size, ptrdiff_t align);

// Determine if the given address lies within the managed region. The
// status of the pointed-at memory, freed or allocated, is irrelevant.
// Any pointer, even null, may be passed to this function.
static _Bool heap_owned(heap *, void *);

// Retrieve information about the underlying heap block for an address
// lying anywhere within that block. Internal pointers are allowed, but
// not one-past-the-end pointers. Returns zero if the pointer does not
// fall within allocation. Any pointer is permitted, even null.
//
// The returned information could be used to build a realloc(3) or as
// part of a garbage collector.
static heap_block heap_getblock(heap *, void *);

// Release an allocation. The pointer may point anywhere within the
// allocation. Internal pointers are allowed, barring HEAP_STRICT, but
// not one-past-the-end pointers, which likely point into another block.
static void heap_free(heap *, void *);


// Implementation

#define heap_assert(c)      while (!(c)) *(volatile int *)0 = 0
#define heap_bump(a, t, n)  (t *)heap_bumpalloc(a, sizeof(t), n)

typedef   signed int       i32;
typedef unsigned int       u32;
typedef          ptrdiff_t iz;
typedef          size_t    uz;
typedef          char      byte;

// A free memory block becomes a doubly-linked heap_node.
typedef struct heap_node heap_node;
struct heap_node {
    heap_node **prev;
    heap_node  *next;
};

struct heap {
    void       *base;
    u32        *status;
    heap_node **free;
    i32         max;
    i32         flags;
};

typedef struct {
    byte *beg;
    byte *end;
} heap_arena;

static void *heap_memset(void *p, byte x, iz len)
{
    byte *d = p;
    for (iz i = 0; i < len; i++) {
        d[i] = x;
    }
    return p;
}

static void *heap_bumpalloc(heap_arena *a, iz size, iz count)
{
    iz pad = (uz)a->end & (sizeof(void *) - 1);
    if (count > (a->end - a->beg - pad)/size) return 0;
    return heap_memset(a->end -= pad + size*count, 0, size*count);
}

static void heap_popblock(heap_node *h)
{
    if (h->prev) *h->prev = h->next;
    if (h->next) h->next->prev = h->prev;
}

static void heap_pushblock(heap_node **prev, heap_node *h)
{
    h->prev = prev;
    h->next = *prev;
    *prev = h;
    if (h->next) h->next->prev = &h->next;
}

// Retrieve the status bit index for a particular block.
static iz heap_getbit(heap *h, heap_node *n, i32 exp)
{
    iz r = (((iz)1<<(h->max - exp)) - 1) +
           (((uz)n - (uz)h->base)>>exp);
    return r;
}

static void heap_markused(heap *h, heap_node *n, i32 exp)
{
    iz bit = heap_getbit(h, n, exp);
    h->status[bit>>5] |= (u32)1<<(bit&31);
}

static void heap_markfree(heap *h, heap_node *n, i32 exp)
{
    iz bit = heap_getbit(h, n, exp);
    h->status[bit>>5] &= ~((u32)1<<(bit&31));
}

static u32 heap_isused(heap *h, heap_node *n, i32 exp)
{
    iz bit = heap_getbit(h, n, exp);
    return h->status[bit>>5] & ((u32)1<<(bit&31));
}

static heap_node *heap_buddy(heap *h, heap_node *n, i32 exp)
{
    iz off = (uz)n - (uz)h->base;
    off ^= (iz)1<<exp;
    return (heap_node *)((byte *)h->base + off);
}

static heap *heap_init(void *buf, iz len, i32 flags)
{
    heap_assert(len >= 0);

    // Align the region if needed
    iz pad = -(uz)buf & ((1<<HEAP_MIN) - 1);
    if (!buf || len<pad) return 0;  // too small
    buf  = (char *)buf + pad;
    len -= pad;

    // Determine the largest possible upper bound. In other words, the
    // largest "square" within the region.
    i32 max = HEAP_MIN;
    for (; (iz)2<<max <= len; max++) {}

    // Keep shrinking the square until everything fits
    for (; max > HEAP_MIN; max--) {
        heap_arena temp = {};
        temp.beg = buf;
        temp.end = temp.beg + len;

        heap_node **free   = heap_bump(&temp, heap_node *, max-HEAP_MIN+1);
        iz          total  = (iz)1<<max;
        iz          nints  = (iz)1<<(max - HEAP_MIN + 1 - 5);
        u32        *status = heap_bump(&temp, u32, nints);
        heap       *h      = heap_bump(&temp, heap, 1);
        if (free && status && h && total<=temp.end-temp.beg) {
            h->base   = buf;
            h->status = status;
            h->free   = free;
            h->max    = max;
            h->flags  = flags;
            heap_pushblock(&h->free[h->max-HEAP_MIN], h->base);
            return h;
        }
    }
    return 0;  // too small
}

static void *heap_alloc1(heap *h, iz size)
{
    heap_assert(size >= 0);
    if ((iz)1<<h->max < size) {
        return 0;  // too large (OOM)
    }

    // Determine the size class
    i32 exp = HEAP_MIN;
    for (; (iz)1<<exp < size; exp++) {}

    // Find smallest available heap_node that fits
    i32 i = exp;
    for (; i<h->max && !h->free[i-HEAP_MIN]; i++) {}
    if (!h->free[i-HEAP_MIN]) {
        return 0;  // none available (OOM)
    }

    // Split until it is as small as possible
    for (; i > exp; i--) {
        heap_node *lo = h->free[i-HEAP_MIN];
        heap_markused(h, lo, i);  // mark parent heap_node as used
        heap_popblock(lo);
        heap_node *hi = heap_buddy(h, lo, i-1);
        heap_pushblock(&h->free[i-1-HEAP_MIN], hi);
        heap_pushblock(&h->free[i-1-HEAP_MIN], lo);
    }

    heap_node *n = h->free[exp-HEAP_MIN];
    heap_popblock(n);
    heap_markused(h, n, exp);
    return heap_memset(n, 0, (iz)1<<exp);
}

static void *heap_alloc3(heap *h, iz count, iz size, iz align)
{
    heap_assert(align >  0);
    heap_assert(count >= 0);
    heap_assert(size  >  0);
    heap_assert(!(align & (align - 1)));

    if (count > ((iz)1<<h->max)/size) {
        return 0;  // too large (OOM)
    }

    if (align <= (iz)1<<HEAP_MIN) {
        return heap_alloc1(h, count*size);
    }

    void *r = heap_alloc1(h, count*size + (align - 1));
    iz pad = -(uz)r & (align - 1);
    return (void *)((uz)r + pad);
}

static void *heap_alloc2(heap *h, iz count, iz size)
{
    return heap_alloc3(h, count, size, 1);
}

static _Bool heap_owned(heap *h, void *p)
{
    uz beg = (uz)h->base;
    uz end = (uz)h->base + ((iz)1<<h->max);
    uz u   = (uz)p;
    return u>=beg && u<end;
}

static heap_block heap_fastgetblock(heap *h, void *p)
{
    heap_block r = {0};
    for (i32 exp = HEAP_MIN; exp <= h->max; exp++) {
        iz mask  = ((iz)1<<exp) - 1;
        iz shift = ((uz)p - (uz)h->base) & mask;
        p = (void *)((char *)p - shift);
        if (heap_isused(h, p, exp)) {
            r.base = p;
            r.size = (iz)1<<exp;
            r.exp  = exp;
            return r;
        }
    }
    return r;
}

static heap_block heap_getblock(heap *h, void *p)
{
    heap_block null = {0};
    if (!heap_owned(h, p)) return null;

    heap_block b = heap_fastgetblock(h, p);
    if (b.exp == HEAP_MIN) return b;

    heap_node *n = b.base;
    if (heap_isused(h, n, b.exp-1)) return null;
    n = heap_buddy(h, n, b.exp-1);
    if (heap_isused(h, n, b.exp-1)) return null;

    return b;
}

static void heap_free(heap *h, void *p)
{
    heap_block b = {0};
    if (h->flags & HEAP_DEBUG) {
        heap_assert(*h->status);  // empty heap?
        b = heap_getblock(h, p);
        heap_assert(b.base);
        heap_memset(b.base, (byte)0xa5, b.size);
    } else {
        b = heap_fastgetblock(h, p);
    }

    if (h->flags & HEAP_STRICT) {
        heap_assert(p == b.base);
    }

    heap_node *n   = b.base;
    i32        exp = b.exp;
    heap_markfree(h, n, exp);
    for (; exp < h->max; exp++) {
        heap_node *buddy = heap_buddy(h, n, exp);
        if (heap_isused(h, buddy, exp)) break;
        heap_popblock(buddy);
        n = (uz)buddy<(uz)n ? buddy : n;
        heap_markfree(h, n, exp+1);
    }
    heap_pushblock(&h->free[exp-HEAP_MIN], n);
}


// Test / Demo

#define W32(r) __declspec(dllimport) r __stdcall
W32(void)   ExitProcess(i32);
W32(void *) VirtualAlloc(uz, iz, i32, i32);

void mainCRTStartup(void)
{
    i32    exp = 26;
    iz     cap = ((iz)1<<exp) + ((iz)1<<(exp-6)) + ((iz)1<<12);
    byte  *mem = VirtualAlloc(0x10000000, cap, 0x3000, 4);
    i32    off = 9;  // test misalignment
    heap  *h   = heap_init(mem+off, cap-off, HEAP_DEBUG);

    // Test basic alloc and free
    void *p = heap_alloc1(h, 1);
    heap_assert(heap_getblock(h, p).size == 1<<HEAP_MIN);
    heap_free(h, p);
    for (iz i = 0; i < (iz)1<<(h->max - HEAP_MIN + 1 - 5); i++) {
        heap_assert(!h->status[i]);
    }

    // Test aligned allocation
    int *junk = heap_new(h, 1000, int);
    p = heap_alloc3(h, 1, 4096, 4096);
    heap_assert(!((uz)p & 0xfff));
    heap_free(h, p);
    heap_free(h, junk);

    // Allocate as much as possible in 64-byte chunks
    i32    nexp    = 6;
    iz     nnodes = (iz)1<<(h->max-nexp);
    char **nodes  = VirtualAlloc(0, sizeof(void *)*nnodes, 0x3000, 4);
    for (iz i = 0; i < nnodes; i++) {
        nodes[i] = heap_alloc2(h, 1, 1<<nexp);
        heap_assert(nodes[i]);
        heap_assert(heap_owned(h, nodes[i]));
        heap_assert(heap_getblock(h, nodes[i]).size == 1<<nexp);
        for (i32 n = 0; n < (1<<nexp)-1; n++) {
            void *base = heap_getblock(h, nodes[i]+n).base;
            heap_assert(nodes[i] == base);
        }
        heap_memset(nodes[i], (byte)0xff, 1<<nexp);
    }
    heap_assert(!heap_alloc2(h, 1, 1));

    // Test freeing in a random order
    unsigned long long rng = 1;
    for (iz i = nnodes-1; i > 0; i--) {
        rng = rng*0x3243f6a8885a308d + 1;
        iz j = (iz)(((rng>>32)*(i+1))>>32);
        heap_free(h, nodes[j]);
        heap_assert(!heap_getblock(h, nodes[j]).base);
        nodes[j] = nodes[i];
    }

    ExitProcess(0);
}
