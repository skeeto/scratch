// Find 64-bit hash collisions using a rainbow table
//   $ cc -nostartfiles -fno-builtin -O3 -o rainbow.exe rainbow.c
//   $ ./rainbow
// Prints string collision pairs, one per line, until running out of
// memory or manually stopped.
//
// This is free and unencumbered software released into the public domain.

#define assert(c)   while (!(c)) __builtin_trap()
#define countof(a)  (size)(sizeof(a) / sizeof(*(a)))
#define new(a, t)   (t *)alloc(a, sizeof(t))

typedef __UINT8_TYPE__   u8;
typedef __INT32_TYPE__   b32;
typedef __INT32_TYPE__   i32;
typedef __UINT64_TYPE__  u64;
typedef __PTRDIFF_TYPE__ size;
typedef __UINTPTR_TYPE__ uptr;
typedef char             byte;

// Platform interface. Porting note: Implement this function, and from
// the process entry point call worker() on one thread per CPU core.
static b32 fullwrite(u8 *, i32 len);

// Target hash function in which to find collisions.
static u64 hash64(u8 *s, size len)
{
    u64 h = 0x100;
    for (size i = 0; i < len; i++) {
        h ^= s[i];
        h *= 1111111111111111111u;
    }
    return h ^ h>>32;
}

static void stringize(u8 s[13], u64 h)
{
    static const u8 base32[32] = "abcdefghijkmnpqrstuvwxyz23456789";
    s[ 0] = base32[(h>>60)&31]; s[ 1] = base32[(h>>55)&31];
    s[ 2] = base32[(h>>50)&31]; s[ 3] = base32[(h>>45)&31];
    s[ 4] = base32[(h>>40)&31]; s[ 5] = base32[(h>>35)&31];
    s[ 6] = base32[(h>>30)&31]; s[ 7] = base32[(h>>25)&31];
    s[ 8] = base32[(h>>20)&31]; s[ 9] = base32[(h>>15)&31];
    s[10] = base32[(h>>10)&31]; s[11] = base32[(h>> 5)&31];
    s[12] = base32[(h>> 0)&31];
}

// Computes the next hash value in the chain.
static u64 next(u64 h)
{
    u8 key[13];
    stringize(key, h);
    return hash64(key, countof(key));
}

typedef struct {
    byte *beg;
    byte *end;
} arena;

static byte *alloc(arena *a, size objsize)
{
    size avail = a->end - a->beg;
    if (avail < objsize) {
        assert(0);
    }
    byte *r = a->beg;
    for (size i = 0; i < objsize; i++) {
        r[i] = 0;
    }
    a->beg += objsize;
    return r;
}

static u64 permute64(u64 x)
{
    x += 1111111111111111111u; x ^= x >> 32;
    x *= 1111111111111111111u; x ^= x >> 32;
    return x;
}

// Concurrent u64-to-64 hash map
typedef struct map map;
struct map {
    map *child[4];
    u64  key;
    u64  val;
};

// Insert key/value into the map and return the entry. May be called
// concurrenty from multiple threads.
static map *upsert(map **m, u64 key, u64 val, arena *a)
{
    for (u64 h = permute64(key);; h <<= 2) {
        map *n = __atomic_load_n(m, __ATOMIC_ACQUIRE);
        if (!n) {
            if (!a) {
                return 0;
            }
            arena rollback = *a;
            map *new = new(a, map);
            new->key = key;
            new->val = val;
            i32 pass = __ATOMIC_RELEASE;
            i32 fail = __ATOMIC_ACQUIRE;
            if (__atomic_compare_exchange_n(m, &n, new, 0, pass, fail)) {
                return new;
            }
            *a = rollback;
        }
        if (n->key == key) {
            return n;
        }
        m = &n->child[h>>62];
    }
}

static b32 terminal(u64 h)
{
    u64 mask = ((u64)1<<22) - 1;
    return !(mask & h);
}

static map *makechain(u64 beg, arena *a)
{
    map *chain = 0;
    u64 end = beg;
    for (u64 len = 0;; len++) {
        u64 prev = end;
        end = next(end);
        upsert(&chain, end, prev, a);
        if (terminal(end)) {
            return chain;
        }
    }
}

typedef struct {
    u64 hash1;
    u64 hash2;
} collision;

static collision recover(u64 beg1, u64 beg2, arena scratch)
{
    map *chain = makechain(beg1, &scratch);
    u64 end = beg2;
    for (;;) {
        u64 prev = end;
        end = next(end);
        map *collide = upsert(&chain, end, 0, 0);
        if (collide) {
            collision r = {0};
            r.hash1 = collide->val;
            r.hash2 = prev;
            return r;
        }
        assert(!terminal(end));
    }
}

// Call from the platform layer with a pointer to the shared hash-trie, a
// small+unique thread id, and a thread-local arena.
static void worker(map **seen, u64 seed, i32 tid, arena perm)
{
    u64 counter = (u64)tid << 48;
    u64 beg = permute64(counter++ ^ seed);
    u64 end = beg;
    for (;;) {
        end = next(end);
        if (terminal(end)) {
            map *entry = upsert(seen, end, beg, &perm);
            if (entry->val != beg) {
                collision c = recover(entry->val, beg, perm);
                u8 s[13+1+13+1];
                stringize(s+ 0, c.hash1); s[13] = ' ';
                stringize(s+14, c.hash2); s[27] = '\n';
                fullwrite(s, countof(s));
            }
            end = beg = permute64(counter++ ^ seed);
        }
    }
}


#ifdef _WIN32
typedef i32 (*thrdfunc)(void *) __attribute((stdcall));
typedef struct {
    i32 a, b;
    uptr c, d, e;
    i32 nproc, g, h, i;
} sysinfo;

#define W32 __attribute((dllimport, stdcall))
W32 i32   CreateThread(void *, size, thrdfunc, void *, i32, i32 *);
W32 void  ExitProcess(i32) __attribute((noreturn));
W32 i32   GetStdHandle(i32);
W32 void  GetSystemInfo(sysinfo *);
W32 byte *VirtualAlloc(byte *, size, i32, i32);
W32 b32   WriteFile(uptr, u8 *, i32, i32 *, void *);

static arena newarena(size cap)
{
    arena a = {0};
    a.end = a.beg = VirtualAlloc(0, cap, 0x3000, 4);
    a.end += cap;
    return a;
}

static b32 fullwrite(u8 *buf, i32 len)
{
    return !WriteFile(GetStdHandle(-11), buf, len, &len, 0);
}

typedef struct {
    map **seen;
    u64   seed;
    i32   tid;
    arena perm;
} threadinfo;

__attribute((stdcall, force_align_arg_pointer))
static i32 threadentry(void *arg)
{
    threadinfo *info = arg;
    worker(info->seen, info->seed, info->tid, info->perm);
    ExitProcess(0);
}

__attribute((force_align_arg_pointer))
void mainCRTStartup(void)
{
    enum { THREADMEM=1<<30 };
    sysinfo si = {0};
    GetSystemInfo(&si);
    i32 nthreads = si.nproc;

    u64 seed;
    asm volatile ("rdrand %0" : "=r"(seed));

    map *seen = 0;
    for (i32 i = 0; i < nthreads; i++) {
        arena perm = newarena(THREADMEM);
        threadinfo *t = new(&perm, threadinfo);
        t->seen = &seen;
        t->seed = seed;
        t->tid  = i;
        t->perm = perm;
        if (i == nthreads-1) {
            threadentry(t);
        }
        CreateThread(0, 0, threadentry, t, 0, 0);
    }
}
#endif
