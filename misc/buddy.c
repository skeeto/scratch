// Buddy Allocator with Garbage Collector
//
// Standout features:
// * Internal pointers supported by all pointer-accepting interfaces
// * Aligned allocation (built atop internal pointers)
// * Safe queries on any pointer: non-owned pointers return blank data
// * Robust double-free detection (optional)
// * Low memory overhead (<1.6%), no allocation block prefixes
// * No libc needed, platform agnostic across 32-and 64-bit hosts
// * Conservative mark-and-sweep garbage collector with flexible API
//
// This is free and unencumbered software released into the public domain.


// Interface

#include <stddef.h>

// Recommended as the primary allocation interface. Normal code should
// not operate on sizes.
#define heap_new(h, n, t)  (t *)heap_alloc3(h, n, sizeof(t), _Alignof(t))

enum {
    HEAP_DEBUG  = 1 <<  8,
    HEAP_STRICT = 1 <<  9,
    HEAP_GC     = 1 << 10,
};

typedef struct heap heap;

typedef struct {
    void     *base;
    ptrdiff_t size;
    int       exp;   // size class: size = (ptrdiff_t)1<<exp
} heap_block;

// Initialize a heap for allocating out of the given memory region. The
// region may have any alignment. Flags are bitwise-OR of zero or more:
//
// * HEAP_DEBUG
//     Memory is pattern-filled on free, and double-frees are detected.
//     Introduces a small performance cost to heap_free().
//
// * HEAP_STRICT
//     Internal pointers are unsupported by heap_free(), and attempts to
//     use them will abort. Incompatible with over-aligned allocations.
//     Does not speed up freeing.
//
// * HEAP_GC
//     Allocate a marks bit array for the conservative mark-and-sweep
//     garbage collector. Required for heap_{startgc,mark,sweep}(). This
//     array doubles memory overhead.
//
// * The minimum allocation/alignment exponent
//     Rounds up to 3 (8-byte) on 32-bit and 4 (16-byte) on 64-bit.
//
// Returns null if the region is too small.
//
// Slightly more than 1/64th of the region is used for bookkeeping, and
// the most efficiently-used regions will be about that much larger than
// a power of two. For instance, allocate a virtual memory of size:
//
//   (1<<N) + (1<<(N-6)) + page_size
//   heap     heapstate    misc.
//
// If using garbage collection, use 1<<(N-5) for the heapstate.
static heap *heap_init(void *, ptrdiff_t, int flags);

// Allocate zero-initialized memory, like malloc(3). Returns null if the
// memory could not be allocated. Alignment is 8-byte on 32-bit and
// 16-byte on 64-bit, or larger if an exponent was set in the flags.
// This is the lowest-level allocator and should generally be avoided as
// error-prone.
static void *heap_alloc1(heap *, ptrdiff_t size);

// Allocate zero-initialized memory, like calloc(3). Returns null if the
// memory could not be allocated. Alignment matches heap_alloc1().
static void *heap_alloc2(heap *, ptrdiff_t n, ptrdiff_t size);

// Allocate zero-initialized memory, like aligned_alloc(3). Returns null
// if the memory could not be allocated. Alignment must be a power of
// two, which excludes zero. Regardless of the request, the minimum
// alignment will be the same as heap_alloc1().
static void *heap_alloc3(heap *, ptrdiff_t n, ptrdiff_t size, ptrdiff_t align);

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
// Returns the real allocation size that was freed.
static ptrdiff_t heap_free(heap *, void *);

// Zero all reachability marks in preparation for garbage collection.
static void heap_startgc(heap *);

// Mark this object and all objects reachable through it, including
// through internal pointers. Any pointer is permitted, and if it does
// not point into a live object then it is ignored. Use this to share
// the reachability roots to the garbage collector.
//
// The queue is a workspace buffer of length (iz)1<<(max-min).
static void heap_mark(heap *, void *, void **queue);

// Like heap_mark(), but recurses through the reachability graph instead
// of using a temporary workspace. Only use if your data structures are
// guaranteed to be shallowly nested!
static void heap_mark_recursive(heap *, void *);

// Free objects that have not been marked. Completes garbage collection.
// Returns the total number of bytes freed.
static ptrdiff_t heap_sweep(heap *);


// Implementation

#define heap_assert(c)      while (!(c)) *(volatile int *)0 = 0
#define heap_bump(a, t, n)  (t *)heap_bumpalloc(a, sizeof(t), n)

typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef   signed long long i64;
typedef unsigned long long u64;
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
    u32        *marks;
    i32         min;
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

static void heap_memcpy(void *restrict dst, void *restrict src, iz len)
{
    byte *d = dst;
    byte *s = src;
    for (; len; len--) *d++ = *s++;
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

    i32 min = flags & 0xff;
    heap_assert(min < (i32)sizeof(iz)*8);
    i32 minmin = 2 + ((i32)sizeof(void *)>>2);
    min = min<minmin ? minmin : min;

    // Align the region if needed
    iz pad = -(uz)buf & (((iz)1<<min) - 1);
    if (!buf || len<pad) return 0;  // too small
    buf  = (char *)buf + pad;
    len -= pad;

    // Determine the largest possible upper bound. In other words, the
    // largest "square" within the region.
    i32 max = min;
    for (; (iz)2<<max <= len; max++) {}

    // Keep shrinking the square until everything fits
    for (; max > min; max--) {
        heap_arena temp = {};
        temp.beg = buf;
        temp.end = temp.beg + len;

        heap_node **free   = heap_bump(&temp, heap_node *, max-min+1);
        iz          total  = (iz)1<<max;
        iz          nints  = max-min<4 ? 1 : (iz)1<<(max - min + 1 - 5);
        u32        *status = heap_bump(&temp, u32, nints);
        u32        *marks  = 0;
        if (flags & HEAP_GC) {
            iz      nmarks = max-min<5 ? 1 : (iz)1<<(max - min     - 5);
                    marks  = heap_bump(&temp, u32, nmarks);
            if (!marks) continue;
        }
        heap       *h      = heap_bump(&temp, heap, 1);
        if (free && status && h && total<=temp.end-temp.beg) {
            h->base   = buf;
            h->status = status;
            h->free   = free;
            h->marks  = marks;
            h->min    = min;
            h->max    = max;
            h->flags  = flags;
            heap_pushblock(&h->free[h->max-min], h->base);
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
    i32 exp = h->min;
    for (; (iz)1<<exp < size; exp++) {}

    // Find smallest available heap_node that fits
    i32 i = exp;
    for (; i<h->max && !h->free[i-h->min]; i++) {}
    if (!h->free[i-h->min]) {
        return 0;  // none available (OOM)
    }

    // Split until it is as small as possible
    for (; i > exp; i--) {
        heap_node *lo = h->free[i-h->min];
        heap_markused(h, lo, i);  // mark parent heap_node as used
        heap_popblock(lo);
        heap_node *hi = heap_buddy(h, lo, i-1);
        heap_pushblock(&h->free[i-1-h->min], hi);
        heap_pushblock(&h->free[i-1-h->min], lo);
    }

    heap_node *n = h->free[exp-h->min];
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

    if (align <= (iz)1<<h->min) {
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

static b32 heap_owned(heap *h, void *p)
{
    uz beg = (uz)h->base;
    uz end = (uz)h->base + ((iz)1<<h->max);
    uz u   = (uz)p;
    return u>=beg && u<end;
}

static heap_block heap_fastgetblock(heap *h, void *p)
{
    heap_block r = {0};
    for (i32 exp = h->min; exp <= h->max; exp++) {
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
    if (b.exp == h->min) return b;

    heap_node *n = b.base;
    if (heap_isused(h, n, b.exp-1)) return null;
    n = heap_buddy(h, n, b.exp-1);
    if (heap_isused(h, n, b.exp-1)) return null;

    return b;
}

static iz heap_blockfree(heap *h, heap_block b)
{
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
    heap_pushblock(&h->free[exp-h->min], n);
    return b.size;
}

static iz heap_free(heap *h, void *p)
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

    return heap_blockfree(h, b);
}

static iz heap_getmark(heap *h, void *p)
{
    iz bit = ((uz)p - (uz)h->base)>>h->min;
    return bit;
}

static void heap_markreachable(heap *h, void *p)
{
    iz bit = heap_getmark(h, p);
    h->marks[bit>>5] |= (u32)1<<(bit&31);
}

static u32 heap_isreachable(heap *h, void *p)
{
    iz bit = heap_getmark(h, p);
    return h->marks[bit>>5] & ((u32)1<<(bit&31));
}

static void heap_startgc(heap *h)
{
    heap_assert(h->marks);
    iz nints = h->max-h->min<5 ? 1 : (iz)1<<(h->max - h->min - 5);
    for (iz i = 0; i < nints; i++) {
        h->marks[i] = 0;
    }
}

static b32 heap_shouldqueue(heap *h, void *p)
{
    heap_block b = heap_getblock(h, p);
    if (b.base && !heap_isreachable(h, b.base)) {
        heap_markreachable(h, b.base);
        return 1;
    }
    return 0;
}

static void heap_mark(heap *h, void *p, void **queue)
{
    iz head = 0;
    iz tail = 0;
    if (heap_shouldqueue(h, p)) {
        queue[head++] = p;
    }
    while (head != tail) {
        void *next = queue[tail++];
        heap_block b = heap_getblock(h, next);
        void **beg = b.base;
        void **end = beg + b.size/sizeof(*beg);
        for (; beg < end; beg++) {
            // NOTE: Bypassing strict aliasing via memcpy()
            void *copy;
            heap_memcpy(&copy, beg, sizeof(copy));
            if (heap_shouldqueue(h, copy)) {
                queue[head++] = copy;
            }
        }
    }
}

static void heap_markrecursive(heap *h, void *p)
{
    heap_assert(h->marks);

    heap_block b = heap_getblock(h, p);
    if (!b.base || heap_isreachable(h, b.base)) return;
    heap_markreachable(h, b.base);

    void **beg = b.base;
    void **end = beg + b.size/sizeof(*beg);
    for (; beg < end; beg++) {
        // NOTE: Bypassing strict aliasing via memcpy()
        void *copy;
        heap_memcpy(&copy, beg, sizeof(copy));
        heap_markrecursive(h, copy);
    }
}

static iz heap_sweep_recursive(heap *h, void *p, i32 exp)
{
    iz  total     = 0;
    u32 leftused  = 0;
    u32 rightused = 0;

    if (exp > h->min) {
        void *left = p;
        leftused = heap_isused(h, left, exp-1);
        if (leftused) {
            total += heap_sweep_recursive(h, left, exp-1);
        }

        void *right = heap_buddy(h, left, exp-1);
        rightused = heap_isused(h, right, exp-1);
        if (rightused) {
            total += heap_sweep_recursive(h, right, exp-1);
        }
    }

    if (!leftused && !rightused && !heap_isreachable(h, p)) {
        heap_block b = {0};
        b.base = p;
        b.size = (iz)1<<exp;
        b.exp  = exp;
        total += heap_blockfree(h, b);
    }

    return total;
}

static iz heap_sweep(heap *h)
{
    // NOTE: Recursion depth is bounded to (max - min + 1), controlled
    // through the exp parameter decreasing at each level.
    heap_assert(h->marks);
    if (*h->status) {
        return heap_sweep_recursive(h, h->base, h->max);
    }
    return 0;
}


#if LIBGC && _WIN32
// Single-threaded garbage collector for Windows
//
// Dynamic library (gc.dll, gc.dll.a):
//   $ printf 'LIBRARY gc.dll\nEXPORTS\ngc_alloc\n' >gc.def
//   $ cc -nostartfiles -shared -fno-builtin -DLIBGC -O2
//        -s --entry 0 -Wl,--out-implib=gc.dll.a -o gc.lib buddy.c gc.def
//
// Static library (gc.a):
//   $ cc -nostartfiles -c -fno-builtin -DLIBGC -O2 -o gc.o buddy.c
//   $ ar r gc.a gc.o
//
// Header (gc.h):
//   #pragma once
//   #include <stddef.h>
//   #define new(n, t)  (t *)gc_alloc(n, sizeof(t), _Alignof(t))
//   void *gc_alloc(ptrdiff_t count, ptrdiff_t size, ptrdiff_t align);
//
// Global variables are not scanned, so live objects must always be
// reachable from local variables. This library must be compiled with
// GCC or Clang, but because it lacks CRT dependencies, can be linked
// into a program compilied by any toolchain.

#ifndef GC_EXP
#  define GC_EXP 28  // 256 MiB
#endif

#define W32(r) __declspec(dllimport) r __stdcall
W32(uz)     LoadLibraryA(char *);
W32(void *) GetProcAddress(uz, char *);
W32(void *) OutputDebugStringA(char *);
W32(i32)    QueryPerformanceCounter(i64 *);
W32(i32)    QueryPerformanceFrequency(i64 *);
W32(void *) VirtualAlloc(uz, iz, i32, i32);

typedef struct {
    char *buf;
    i32   len;
    i32   cap;
} chars;

static void gc_prints(chars *b, char *buf, i32 len)
{
    i32 avail = b->cap - b->len;
    i32 count = avail<len ? avail : len;
    __builtin_memcpy(b->buf+b->len, buf, count);
    b->len += count;
}

static void gc_printz(chars *b, iz x)
{
    char  buf[32];
    char *p = buf + 32;
    do *--p = (char)(x%10) + '0';
    while (x /= 10);
    gc_prints(b, p, (i32)(buf+32-p));
}

#if __amd64
typedef struct {
    uz *stacklo;
    uz *stackhi;
    uz *regs[8];
} gc_roots;
#define GC_ROOTS(p, tmp)        \
    asm volatile (              \
        "mov %%rsp,    0(%1)\n" \
        "mov %%gs:(8),   %0\n"  \
        "mov %0,       8(%1)\n" \
        "mov %%rbp,   16(%1)\n" \
        "mov %%rbx,   24(%1)\n" \
        "mov %%rdi,   32(%1)\n" \
        "mov %%rsi,   40(%1)\n" \
        "mov %%r12,   48(%1)\n" \
        "mov %%r13,   56(%1)\n" \
        "mov %%r14,   64(%1)\n" \
        "mov %%r15,   72(%1)\n" \
        : "=&r"(tmp)            \
        : "r"(p)                \
        : "memory"              \
    )

#elif __i386
typedef struct {
    uz *stacklo;
    uz *stackhi;
    uz *regs[4];
} gc_roots;
#define GC_ROOTS(p, tmp)        \
    asm volatile (              \
        "mov %%esp,    0(%1)\n" \
        "mov %%fs:(4),   %0\n"  \
        "mov %0,       4(%1)\n" \
        "mov %%ebx,    8(%1)\n" \
        "mov %%ebp,   12(%1)\n" \
        "mov %%esi,   16(%1)\n" \
        "mov %%edi,   20(%1)\n" \
        : "=&r"(tmp)            \
        : "r"(p)                \
        : "memory"              \
    )
#endif

void *gc_alloc(iz count, iz size, iz align)
{
    static heap *globalheap = 0;
    static void *markbuffer = 0;
    static iz    markbuflen = 0;
    static i32 (*discardfun)(void *, iz) = 0;
    static enum {UNINIT, FAIL, SUCCESS} init;
    switch (init) {
    case UNINIT:;
        iz    cap = ((iz)1<<GC_EXP) + ((iz)1<<(GC_EXP-5)) + ((iz)1<<12);
        void *mem = VirtualAlloc(0, cap, 0x3000, 4);
        globalheap = mem ? heap_init(mem, cap, HEAP_GC|4) : 0;
        if (!globalheap) {
            init = FAIL;
            return 0;
        }

        markbuflen = sizeof(void *)<<(globalheap->max - globalheap->min);
        markbuffer = VirtualAlloc(0, markbuflen, 0x3000, 4);
        if (!markbuffer) {
            init = FAIL;
            return 0;
        }

        uz dll = LoadLibraryA("kernel32.dll");
        discardfun = dll ? GetProcAddress(dll, "DiscardVirtualMemory") : 0;
        init = SUCCESS;
        break;
    case FAIL:
        return 0;
    case SUCCESS:
        break;
    }

    void *r = heap_alloc3(globalheap, count, size, align);
    if (r) return r;

    i64 start;
    QueryPerformanceCounter(&start);
    heap_startgc(globalheap);

    // Gather reachability roots from the current thread
    gc_roots roots;
    register uz tmp;
    GC_ROOTS(&roots, tmp);

    // Treat volatile registers as roots
    i32 nregs = sizeof(roots.regs)/sizeof(*roots.regs);
    for (i32 i = 0; i < nregs; i++) {
        heap_mark(globalheap, roots.regs[i], markbuffer);
    }

    // Scan the stack for pointers
    for (uz *p = roots.stacklo; p < roots.stackhi; p++) {
        heap_mark(globalheap, (void *)*p, markbuffer);
    }

    i64 stop;
    iz freed = heap_sweep(globalheap);
    QueryPerformanceCounter(&stop);

    static i64 frequency = 0;
    if (!frequency) QueryPerformanceFrequency(&frequency);

    chars msg = {0};
    msg.buf = (char[64]){0};
    msg.cap = 63;
    gc_prints(&msg, "gc_alloc: freed ", 16);
    gc_printz(&msg, freed);
    gc_prints(&msg, " bytes in ", 10);
    gc_printz(&msg, (iz)(1e6f*(float)(stop-start)/(float)(i32)frequency));
    gc_prints(&msg, " us\n", 4);
    OutputDebugStringA(msg.buf);

    if (discardfun) discardfun(markbuffer, markbuflen);

    // Try again
    return heap_alloc3(globalheap, count, size, align);
}


#elif TEST && _WIN32
// Test
// $ cc -nostartfiles -DTEST -o buddy.exe buddy.c
// $ cl /DTEST buddy.c /link /subsystem:console kernel32.lib
// $ ./buddy && echo ok

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
    heap_assert(h);

    // Test basic alloc and free
    void *p = heap_alloc1(h, 1);
    heap_assert(heap_getblock(h, p).size == 1<<h->min);
    heap_free(h, p);
    for (iz i = 0; i < (iz)1<<(h->max - h->min + 1 - 5); i++) {
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
    u64 rng = 1;
    for (iz i = nnodes-1; i > 0; i--) {
        rng = rng*0x3243f6a8885a308d + 1;
        iz j = (iz)(((rng>>32)*(i+1))>>32);
        heap_free(h, nodes[j]);
        heap_assert(!heap_getblock(h, nodes[j]).base);
        nodes[j] = nodes[i];
    }

    // Test garbage collection
    h = heap_init(mem, 1<<16, HEAP_DEBUG|HEAP_GC|6);
    heap_assert(h);
    heap_assert(h->min == 6);
    while (heap_alloc1(h, 1)) {}
    heap_startgc(h);
    heap_sweep(h);
    heap_assert(!h->status[0]);  // all freed?

    // Test garbage collection on a linked list
    typedef struct node node;
    struct node {
        i32  value;
        node *next;
    };
    node  *head = 0;
    node **tail = &head;
    for (i32 i = 0;; i++) {
        node *last = heap_new(h, 1, node);
        if (!last) break;
        last->value = i;
        *tail = last;
        tail = &last->next;
    }
    heap_startgc(h);
    heap_markrecursive(h, head);
    heap_sweep(h);
    heap_assert(!heap_alloc1(h, 1));

    uz lostnode = (uz)head;
    head = head->next;  // "leak" first node
    heap_startgc(h);
    heap_markrecursive(h, head);
    heap_sweep(h);  // should free first node
    uz newnode = (uz)heap_alloc1(h, 1);
    heap_assert(lostnode == newnode);

    ExitProcess(0);
}
#endif
