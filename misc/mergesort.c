// Stable Queue Mergesort and Stack Mergesort
//
// By default it tests/benchmarks queue mergesort. Use -DDFS to enable
// stack mergesort instead. Queue mergesort temporary work space is
// itself a linked list and drawn from a scratch arena.
//
// Note how the benchmark slows down as it runs. The list starts in tidy
// memory order but is gradually shuffled through reuse, randomizing
// traversal. Then cache miss effects kick in and dramatically hurt
// performance. Without these cache misses, queue and stack performance
// is equal, but under random traversal, stack mergesort performs much
// better. LIFO concentrates the most active nodes, reducing cache
// misses, while FIFO is prone to the worst cache miss effects.
//
// Ref: https://gist.github.com/maxgoren/e3c7607abe164ee448e652d7d63bfbb7
// Ref:  http://www.maxgcoding.com/queue-mergesort-a-comparison-optimal-bottom-up-sort-for-linked-lists/
// Ref: https://sedgewick.io/wp-content/themes/sedgewick/papers/1993Queue.pdf
// Ref: https://old.reddit.com/r/C_Programming/comments/15lpjtl/_/jvhujb2/
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>

typedef int Bool;
typedef int32_t I32;
typedef uint64_t U64;
typedef ptrdiff_t Size;
typedef unsigned char Byte;

#define ASSERT(c) if (!(c)) *(volatile int *)0 = 0
#define SIZEOF(x) (Size)(sizeof(x))
#define NEW(a, type, n) (type *)alloc(a, sizeof(type)*(n), _Alignof(type))
#define PUTS(out, s) print(out, (Byte *)s, SIZEOF(s)-1)

// To port, implement these two functions on your platform.
static Bool  oswrite(I32, Byte *, I32);
static Byte *osalloc(Size);

typedef struct {
    Byte *mem;
    Size off;
    Size cap;
} Arena;

static Arena *newarena(void)
{
    Size cap = (Size)1 << 28;
    Byte *mem = osalloc(cap);
    Arena *arena = (Arena *)mem;
    if (arena) {
        arena->mem = mem;
        arena->off = SIZEOF(Arena);
        arena->cap = cap;
    }
    return arena;
}

static void reset(Arena *a)
{
    a->off = SIZEOF(Arena);
}

static Byte *alloc(Arena *a, Size size, Size align)
{
    Size avail = a->cap - a->off;
    Size padding = -a->off & (align - 1);
    if (avail-padding < size) {
        ASSERT(0);  // OOM
    }
    Byte *r = a->mem + a->off + padding;
    a->off += padding + size;
    for (Size i = 0; i < size; i++) {
        r[i] = 0;
    }
    return r;
}

typedef struct Node {
    struct Node *next;
    I32 value;
    I32 order;  // stability validation
} Node;

static Node *merge(Node *a, Node *b)
{
    Node  *head = 0;
    Node **tail = &head;
    while (a && b) {
        if (b->value < a->value) {
            *tail = b;
            tail = &b->next;
            b = b->next;
        } else {
            *tail = a;
            tail = &a->next;
            a = a->next;
        }
    }
    *tail = a ? a : b;
    return head;
}

// Stable Queue Mergesort, O(n) worst case space.
static Node *sortbfs(Node *ns, Arena *scratch)
{
    typedef struct Queue {
        struct Queue *next;
        Node *list;
    } Queue;
    Queue  *head = 0;
    Queue **tail = &head;

    // Build a queue out of sorted runs
    while (ns) {
        Queue *q = NEW(scratch, Queue, 1);
        q->list = ns;
        while (ns->next && ns->value<=ns->next->value) {
            ns = ns->next;
        }
        Node *final = ns;
        ns = ns->next;
        final->next = 0;
        *tail = q;
        tail = &q->next;
    }

    while (head->next) {
        tail = &head;
        for (Queue *q = head; q; q = q->next ? q->next->next : 0) {
            Node *a = q->list;
            Node *b = q->next ? q->next->list : 0;
            q->list = merge(a, b);
            *tail = q;
            tail = &q->next;
        }
        *tail = 0;
    }
    return head->list;
}

// Stable Stack Mergesort, O(log n) worst case space.
static Node *sortdfs(Node *head)
{
    I32 len = 0;
    Node *list[64];
    Size depth[64];

    while (head) {
        list[len] = head;
        depth[len++] = 0;
        while (head->next && head->value<=head->next->value) {
            head = head->next;
        }
        Node *last = head;
        head = head->next;
        last->next = 0;

        for (; len>1 && depth[len-1]==depth[len-2]; len--) {
            list[len-2] = merge(list[len-2], list[len-1]);
            depth[len-2]++;
        }
    }

    for (; len > 1; len--) {
        list[len-2] = merge(list[len-2], list[len-1]);
    }
    return len ? list[0] : 0;
}

typedef struct {
    Byte *buf;
    I32   len;
    I32   cap;
    I32   fd;
    Bool  err;
} Out;

static Out *newout(Arena *arena, I32 fd)
{
    Out *out = NEW(arena, Out, 1);
    out->cap = 1<<14;
    out->buf = NEW(arena, Byte, out->cap);
    out->fd = fd;
    return out;
}

static void flush(Out *out)
{
    if (!out->err && out->len) {
        out->err |= !oswrite(out->fd, out->buf, out->len);
        out->len = out->err ? out->len : 0;
    }
}

static void print(Out *out, Byte *buf, Size len)
{
    Byte *end = buf + len;
    while (!out->err && buf<end) {
        I32 avail = out->cap - out->len;
        I32 count = end-buf<avail ? (I32)(end-buf) : avail;
        Byte *dst = out->buf + out->len;
        for (I32 i = 0; i < count; i++) {
            dst[i] = buf[i];
        }
        buf += count;
        out->len += count;
        if (out->len == out->cap) {
            flush(out);
        }
    }
}

static void printi32(Out *out, I32 v)
{
    Byte tmp[32];
    Byte *e = tmp + SIZEOF(tmp);
    Byte *p = e;
    I32 t = v<0 ? v : -v;
    do {
        *--p = (Byte)('0' - t%10);
    } while (t /= 10);
    p[-1] = '-';
    p -= v < 0;
    print(out, p, e-p);
}

static void printlist(Out *out, Node *ns)
{
    for (Node *node = ns; node; node = node->next) {
        printi32(out, node->order);
        PUTS(out, "\t");
        printi32(out, node->value);
        PUTS(out, "\n");
    }
}

static I32 testmain(void)
{
    Arena *arena = newarena();
    Arena *scratch = newarena();
    Out *stdout = newout(arena, 1);
    U64 rng = 1;
    I32 runs = 20;
    I32 numnodes = 1000000;

    Node *nodes = 0;
    for (I32 i = 0; i < numnodes; i++) {
        Node *node = NEW(arena, Node, 1);
        node->next = nodes;
        nodes = node;
    }
    printi32(stdout, (I32)arena->off);
    PUTS(stdout, " arena bytes used\n");

    for (I32 i = 0; i < runs; i++) {
        I32 prev = 0;
        I32 order = 0;
        for (Node *node = nodes; node; node = node->next) {
            rng = rng*0x3243f6a8885a308d + 1;
            if (order>0 && ((rng>>32) & 0x1f)) {
                node->value = prev;  // continue run
            } else {
                prev = node->value = (I32)(rng >> 44);
            }
            node->order = order++;
        }

        reset(scratch);
        Size off = scratch->off;
        #ifdef DFS
        nodes = sortdfs(nodes);
        #else
        nodes = sortbfs(nodes, scratch);
        #endif
        printi32(stdout, (I32)(scratch->off - off));
        PUTS(stdout, " scratch bytes used\n");
        flush(stdout);

        I32 count = 1;
        for (Node *n = nodes; n->next; n = n->next, count++) {
            ASSERT(n->value <= n->next->value);
            ASSERT(n->value<n->next->value || n->order<n->next->order);
        }
        ASSERT(count == numnodes);
    }

    PUTS(stdout, "success\n");
    flush(stdout);
    return stdout->err;
}


#ifdef _WIN32
// $ cc -nostartfiles -o mergesort.exe mergesort.c
// $ cl mergesort.c

#define W32(r) __declspec(dllimport) r __stdcall
W32(void *) GetStdHandle(I32);
W32(Bool) WriteFile(void *, Byte *, I32, I32 *, void *);
W32(Byte *) VirtualAlloc(Byte *, Size, I32, I32);

#ifdef _MSC_VER
  #pragma comment(linker, "/subsystem:console")
  #pragma comment(lib, "kernel32.lib")
  void *memset(void *, int, size_t);
  #pragma function(memset)
  void *memset(void *d, int c, size_t n)
  {
      char *dst = (char *)d;
      for (; n; n--) *dst++ = (char)c;
      return d;
  }
#endif

static Bool oswrite(I32 fd, Byte *buf, I32 len)
{
    void *handle = GetStdHandle(-10 - fd);
    return WriteFile(handle, buf, len, &len, 0);
}

static Byte *osalloc(Size size)
{
    return VirtualAlloc(0, size, 0x3000, 4);
}

I32 mainCRTStartup(void)
{
    return testmain();
}

#else
// $ cc -o mergesort mergesort.c
#include <stdio.h>
#include <stdlib.h>

static Bool oswrite(I32 fd, Byte *buf, I32 len)
{
    FILE *f = fd==1 ? stdout : stderr;
    return fwrite(buf, len, 1, f) && !fflush(f);
}

static Byte *osalloc(Size size)
{
    return malloc(size);
}

int main(void)
{
    return testmain();
}
#endif
