// 3sum problem
//
// In a collection of integers, -1e5 <= n <= +1e5, find 3-tuples summing
// to zero. Do not use the same index more than once, and only produce
// unique-valued tuples (order invariant). Example:
//
// input: {-1, 0, 1, 2, -1, -4}; output: {{-1, -1, 2}, {-1, 0, 1}}
//
// Mostly a little experiment applying my C techniques in C++, making
// tasteful use of some C++ features. I'm quite happy with my span: it
// has nice ergonomics and extends in-place. In a more complex problem
// I'd probably have distinct makefront and makeback so that allocations
// could be made on the back (most cases) without disrupting a span in
// the front.
//
// Curiously, as of this writing, GCC does a great job optimizing the
// recursive solution at (and only at) -O3. Clang does not, producing a
// much slower program.
//
// Porting: Implement monotonic_seconds(), write(), and arena::arena().
// Call run and exit using its returned status.
//
// Ref: https://leetcode.com/problems/3sum/description/
// Ref: https://nullprogram.com/blog/2024/04/14/
// Ref: https://old.reddit.com/r/C_Programming/comments/1c8wtun
// This is free and unencumbered software released into the public domain.

#define assert(c)  while (!(c)) *(volatile int *)0 = 0

typedef unsigned char                 u8;
typedef   signed int                  b32;
typedef   signed int                  i32;
typedef   signed long long            i64;
typedef unsigned long long            u64;
typedef          double               f64;
typedef          char                 byte;
typedef decltype(sizeof(0))           uptr;
typedef decltype((char *)0-(char *)0) isize;
typedef decltype(sizeof(0))           usize;

static f64 monotonic_seconds();           // [platform]
static b32 write(i32 fd, u8 *, i32 len);  // [platform]

template<typename T, isize N>
constexpr isize countof(T (&)[N]) { return N; }

struct arena {
    byte *beg;
    byte *end;
    arena(isize);  // [platform]
};

void *operator new(usize, void *p) { return p; }

template<typename T>
static T *make(arena *perm, isize count = 1)
{
    isize size = sizeof(T);
    isize pad  = -(uptr)perm->beg & (alignof(T) - 1);
    assert(count < (perm->end - perm->beg - pad)/size);
    T *r = (T *)perm->beg + pad;
    perm->beg += size*count + pad;
    for (isize i = 0; i < count; i++) {
        new ((void *)&r[i]) T{};
    }
    return r;
}

template<typename T>
struct span {
    T    *data = 0;
    isize len  = 0;

    span() = default;

    template<isize N>
    span(T const (&a)[N]) : data{(T *)a}, len{N} {}

    span(arena *perm, isize n) : data{make<T>(perm, n)}, len{n} {}

    T &operator[](isize i) { return data[i]; }

    operator T*() { return data; }
};

template<typename T>
static span<T> push(arena *perm, span<T> s, T v)
{
    if ((byte *)(s.data+s.len) != perm->beg) {
        // Cannot extend, make a copy that can extend
        span<T> t(perm, s.len);
        for (isize i = 0; i < s.len; i++) {
            t[i] = s[i];
        }
        s = t;
    }
    *make<T>(perm) = v;
    s.len++;
    return s;
}

struct compmap {
    compmap *child[4];
    i32      index;
};

static u64 hash(i32 x, i32 y)
{
    // NOTE: hash must be commutative
    return 1111111111111111111u * x * y;
}

// Find the index of the complement. If not found, insert and return -1.
static i32 upsert(compmap **m, i32 *nums, i32 index, i32 target, arena *perm)
{
    i32 value = nums[index];
    for (u64 h = hash(value, target-value); *m; h <<= 2) {
        if (value+nums[(*m)->index] == target) {
            return (*m)->index;
        }
        m = &(*m)->child[h>>62];
    }
    *m = make<compmap>(perm);
    (*m)->index = index;
    return -1;
}

struct triple {
    i32 v[3];

    triple() = default;

    triple(i32 *a) : triple{a[0], a[1], a[2]} {}

    triple(i32 x, i32 y, i32 z) : v{x, y, z}
    {
        // network sort to canonicalize
        i32 a, b, t;
        a=v[0]; b=v[2]; t=v[0] = a<b ? a : b; v[2] ^= a ^ t;
        a=v[0]; b=v[1]; t=v[0] = a<b ? a : b; v[1] ^= a ^ t;
        a=v[1]; b=v[2]; t=v[1] = a<b ? a : b; v[2] ^= a ^ t;
    }

    i32 &operator[](isize i) { return v[i]; }

    b32 operator==(triple t) { return t[0]==v[0] && t[1]==v[1] && t[2]==v[2]; }
};

static u64 hash(triple t)
{
    return 1111111111111111111u * t[0] * t[1] * t[2];
}

struct tripleset {
    tripleset *child[4];
    triple     key;
};

// Try to add a triple to the set. True on success.
static b32 insert(tripleset **s, triple key, arena *perm)
{
    for (u64 h = hash(key); *s; h <<= 2) {
        if (key == (*s)->key) {
            return 0;
        }
        s = &(*s)->child[h>>62];
    }
    *s = make<tripleset>(perm);
    (*s)->key = key;
    return 1;
}

static span<triple> threesum_map(span<i32> nums, arena *perm, arena scratch)
{
    span<triple> r;

    for (i32 i = 0; i < nums.len-2; i++) {
        arena temp = scratch;
        compmap *complements = 0;
        i32 target = -nums[i];
        for (i32 j = i+1; j < nums.len; j++) {
            i32 k = upsert(&complements, nums, j, target, &temp);
            if (k >= 0) {
                r = push(perm, r, {nums[i], nums[j], nums[k]});
            }
        }
    }

    // Remove duplicates
    tripleset *seen = 0;
    for (i32 i = 0; i < r.len; i++) {
        if (!insert(&seen, r[i], &scratch)) {
            r[i] = r[--r.len];  // remove
            i--;
        }
    }

    return r;
}

static i32 randint(u64 *rng, i32 lo, i32 hi)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return (i32)(((*rng>>32)*(hi - lo))>>32) + lo;
}

static span<i32> generate(u64 seed, i32 len, arena *perm)
{
    span<i32> nums(perm, len);
    seed += 1111111111111111111u;
    for (i32 i = 0; i < len; i++) {
        nums[i] = randint(&seed, -100000, +100001);
    }
    return nums;
}

struct ctx {
    span<i32> nums;
    arena    *perm;
    i32       buf[3];
};

static span<triple> helper(ctx *c, span<triple> out, i32 sum, i32 i, i32 len)
{
    if (i>=c->nums.len || len==3) {
        if (len==3 && sum==0) {
            out = push(c->perm, out, {c->buf});
        }
        return out;
    }

    c->buf[len] = c->nums[i];
    out = helper(c, out, sum+c->nums[i], i+1, len+1);
    out = helper(c, out, sum,            i+1, len  );
    return out;
}

static span<triple> threesum_recurse(span<i32> nums, arena *perm)
{
    ctx c  = {};
    c.nums = nums;
    c.perm = perm;
    // TODO: avoid/remove duplicates
    return helper(&c, {}, 0, 0, 0);
}

struct bufout {
    u8 *buf;
    i32 len = 0;
    i32 cap;
    i32 fd;
    b32 err = 0;

    bufout(arena *perm, i32 _fd, i32 _cap = 1<<12)
        : buf{make<u8>(perm, _cap)}, cap{_cap}, fd{_fd} { }
};

static void flush(bufout *b)
{
    if (!b->err && b->len) {
        b->err = !write(b->fd, b->buf, b->len);
        b->len = 0;
    }
}

static void print(bufout *b, u8 *buf, isize len)
{
    for (isize off = 0; !b->err && off<len;) {
        i32 avail = b->cap - b->len;
        i32 count = avail<len-off ? avail : (i32)(len-off);
        u8 *dst = b->buf + b->len;
        for (i32 i = 0; i < count; i++) {
            dst[i] = buf[off+i];
        }
        off += count;
        b->len += count;
        if (b->len == b->cap) {
            flush(b);
        }
    }
}

static void print(bufout *b, i32 x)
{
    i32 t = x<0 ? x : -x;
    u8  buf[32];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    do {
        *--beg = '0' - (u8)(t%10);
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    print(b, beg, end-beg);
}

template<isize N>
static void print(bufout *b, char const (&s)[N])
{
    print(b, (u8 *)s, N-1);
}

static void print(bufout *b, triple t)
{
    print(b, t[0]);  print(b, "\t");
    print(b, t[1]);  print(b, "\t");
    print(b, t[2]);  print(b, "\n");
}

static void print(bufout *b, span<triple> r)
{
    for (i32 i = 0; i < r.len; i++) {
        print(b, r[i]);
    }
}

static void validate(span<triple> r)
{
    for (i32 i = 0; i < r.len; i++) {
        assert(r[i][0]+r[i][1]+r[i][2] == 0);
    }
}

static i32 run()
{
    arena perm[1] = {1<<21};  //  2MiB
    arena scratch = {1<<24};  // 16MiB

    #if 0
    i32 example[] = {-1, 0, 1, 2, -1, -4};
    span<i32> nums(example);
    #else
    span<i32> nums = generate(0, 3000, perm);
    #endif

    bufout stdout(&scratch, 1);
    bufout stderr(&scratch, 2);

    {
        f64 start = monotonic_seconds();
        span <triple> r = threesum_map(nums, perm, scratch);
        f64 delta = monotonic_seconds() - start;
        validate(r);
        print(&stderr, "hashmap\t");
        print(&stderr, (i32)r.len);
        print(&stderr, "\t");
        print(&stderr, (i32)(delta * 1e3));
        print(&stderr, "ms\n");
        flush(&stderr);
        print(&stdout, r);
        flush(&stdout);
    }

    {
        f64 start = monotonic_seconds();
        span <triple> r = threesum_recurse(nums, perm);
        f64 delta = monotonic_seconds() - start;
        validate(r);
        print(&stderr, "recurse\t");
        print(&stderr, (i32)r.len);
        print(&stderr, "\t");
        print(&stderr, (i32)(delta * 1e3));
        print(&stderr, "ms\n");
        flush(&stderr);
        print(&stdout, r);
        flush(&stdout);
    }

    return stdout.err;
}


#if _WIN32
// $ cc -nostartfiles -O -o 3sum.exe 3sum.cpp
// $ cl /O2 3sum.cpp /link /subsystem:console kernel32.lib libvcruntime.lib

#define W32(r) extern "C" __declspec(dllimport) r __stdcall
W32(void)   ExitProcess(i32);
W32(uptr)   GetStdHandle(i32);
W32(b32)    QueryPerformanceCounter(i64 *);
W32(b32)    QueryPerformanceFrequency(i64 *);
W32(byte *) VirtualAlloc(uptr, isize, i32, i32);
W32(b32)    WriteFile(uptr, u8 *, i32, i32 *, uptr);

static f64 monotonic_seconds()
{
    static i64 freq;
    if (!freq) QueryPerformanceFrequency(&freq);
    i64 count;
    QueryPerformanceCounter(&count);
    return (double)count / (double)freq;
}

static b32 write(i32 fd, u8 *buf, i32 len)
{
    uptr h = GetStdHandle(-10 - fd);
    return WriteFile(h, buf, len, &len, 0);
}

inline arena::arena(isize cap)
{
    beg = VirtualAlloc(0, cap, 0x3000, 4);
    end = beg + cap;
}

extern "C" { int _fltused; }
extern "C" void mainCRTStartup()
{
    i32 r = run();
    ExitProcess(r);
}


#else  // POSIX
// $ cc -O -o 3sum 3sum.cpp
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static f64 monotonic_seconds()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec/1e9;
}

static b32 write(i32 fd, u8 *buf, i32 len)
{
    for (i32 off = 0; off < len;) {
        i32 r = (i32)write(fd, (void *)(buf+off), len-off);
        if (r < 1) return 0;
        off += r;
    }
    return 1;
}

inline arena::arena(isize cap)
{
    beg = (byte *)malloc(cap);
    end = beg + cap;
}

int main()
{
    i32 r = run();
    return r;
}
#endif
