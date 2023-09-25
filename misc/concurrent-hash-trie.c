// Thread-safe, lock-free hash-trie
// $ cc -g3 -fsanitize=thread,undefined concurrent-hash-trie.c
// $ gdb -ex run ./a.out
//
// The upsert function is like the "standard" upsert except that it uses
// acquire/release atomics to navigate and update trie references.
//
// This is free and unencumbered software released into the public domain.
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define new(a, t, n)  (t *)alloc(a, sizeof(t), _Alignof(t), n, 1)
#define s(cstr)       (str){(byte *)cstr, sizeof(cstr)-1}
#define assert(c)     while (!(c)) __builtin_unreachable()

typedef int           bool;
typedef unsigned char byte;
typedef ptrdiff_t     size;
typedef uintptr_t     uptr;
typedef uint64_t      uint64;

typedef struct {
    byte *beg;
    byte *end;
} arena;

static byte *alloc(arena *a, size objsize, size align, size count, bool zero)
{
    size avail = a->end - a->beg;
    size pad = -(uptr)a->beg & (align - 1);
    if (count > (avail - pad)/objsize) {
        assert(0);
    }
    a->beg += pad;
    byte *r = a->beg;
    a->beg += objsize * count;
    return zero ? memset(r, 0, objsize*count) : r;
}

typedef struct {
    byte *buf;
    size  len;
} str;

static str copyinto(str s, arena *a)
{
    str r = {0};
    r.buf = new(a, byte, s.len);
    memcpy(r.buf, s.buf, s.len);
    r.len = s.len;
    return r;
}

static bool equals(str a, str b)
{
    return a.len==b.len && !memcmp(a.buf, b.buf, a.len);
}

static uint64 hash64(str s)
{
    uint64 h = 0x100;
    for (size i = 0; i < s.len; i++) {
        h ^= s.buf[i];
        h *= 1111111111111111111u;
    }
    return h ^ h>>32;
}

static size itoa(byte *buf, int v)
{
    size len = (v<0) + 1;
    for (int t = v; t /= 10; len++) {}
    int t = v<0 ? v : -v;
    byte *p = buf + len;
    do {
        *--p = '0' - (byte)(t%10);
    } while (t /= 10);
    if (v < 0) {
        *--p = '-';
    }
    return len;
}

typedef struct map map;
struct map {
    map *child[4];
    str  key;
    int  value;
};

// Thread-safe, lock-free insert/search.
static int *upsert(map **m, str key, arena *a)
{
    for (uint64 h = hash64(key);; h <<= 2) {
        map *n = __atomic_load_n(m, __ATOMIC_ACQUIRE);
        if (!n) {
            if (!a) {
                return 0;
            }
            arena rollback = *a;
            map *new = new(a, map, 1);
            new->key = key;
            int pass = __ATOMIC_RELEASE;
            int fail = __ATOMIC_ACQUIRE;
            if (__atomic_compare_exchange_n(m, &n, new, 0, pass, fail)) {
                return &new->value;
            }
            *a = rollback;
        }
        if (equals(n->key, key)) {
            return &n->value;
        }
        m = n->child + (h >> 62);
    }
}

typedef struct {
    arena arena;
    map **root;
    int   start;
    int   stop;
} context;

static void *worker(void *arg)
{
    context ctx = *(context *)arg;
    for (int i = ctx.start; i < ctx.stop; i++) {
        byte buf[32];
        str key = {0};
        key.buf = buf;
        key.len = itoa(buf, i);
        key = copyinto(key, &ctx.arena);
        *upsert(ctx.root, key, &ctx.arena) = i;
    }
    return 0;
}

static arena newarena(arena *base, size cap)
{
    arena r = {0};
    r.beg = alloc(base, 1, 1, cap, 0);
    r.end = r.beg + cap;
    return r;
}

int main(void)
{
    size cap = (size)1<<30;
    byte *heap = malloc(cap);
    arena perm = {0};
    perm.beg = heap;
    perm.end = heap + cap;

    enum { N=32, M=100000 };
    map *nums = 0;
    pthread_t threads[N];
    for (int i = 0; i < N; i++) {
        context *ctx = new(&perm, context, 1);
        ctx->arena = newarena(&perm, 1<<23);
        ctx->root  = &nums;
        ctx->start = M * (i + 0);
        ctx->stop  = M * (i + 1);
        pthread_create(threads+i, 0, worker, ctx);
    }
    for (int i = 0; i < N; i++) {
        pthread_join(threads[i], 0);
    }

    for (int i = 0; i < N*M; i++) {
        byte buf[32];
        str key = {0};
        key.buf = buf;
        key.len = itoa(buf, i);
        assert(*upsert(&nums, key, 0) == i);
    }

    free(heap);
    return 0;
}
