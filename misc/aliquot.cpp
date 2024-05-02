// Aliquot sequences
// $ cc -nostartfiles -fno-exceptions -O -o aliquot.exe aliquot.cpp
// $ cl /kernel /GS- /GR- /O2 aliquot.cpp
//      /link /subsystem:console kernel32.lib libvcruntime.lib
//
// Porting: Implement write(i32, u8 *, i32) and call run(arena).
//
// Ref: https://www.youtube.com/watch?v=OtYKDzXwDEE
// This is free and unencumbered software released into the public domain.

#define assert(c)   while (!(c)) *(volatile int *)0 = 0

typedef unsigned char      u8;
typedef   signed int       b32;
typedef   signed int       i32;
typedef   signed long long i64;
typedef unsigned long long u64;
typedef   signed long long iz;  // only supports 64-bit hosts
typedef unsigned long long uz;  // "
typedef          char      byte;

static b32 write(i32, u8 *, i32);  // [platform]

template<typename T> static u64 hash(T);

void *operator new(uz, void *p) { return p; }

struct arena {
    byte *beg;
    byte *end;
};

template<typename T, typename ...A>
static T *back(iz count, arena *a, A ...args)
{
    iz size = sizeof(T);
    assert(count < (a->end - a->beg)/size);
    T *r = (T *)(a->end -= size*count);
    for (iz i = 0; i < count; i++) new (r+i) T(args...);
    return r;
}

template<typename T, typename ...A>
static T *back(arena *a, A ...args)
{
    return back<T>(1, a, args...);
}

template<typename T, typename ...A>
static T *front(iz count, arena *a, A ...args)
{
    iz size = sizeof(T);
    assert(count < (a->end - a->beg)/size);
    T *r = (T *)a->beg;
    a->beg += size*count;
    for (iz i = 0; i < count; i++) new (r+i) T(args...);
    return r;
}

template<typename T>
struct set {
    set<T> *child[4];
    T       key;
};

template<typename T>
static b32 insert(set<T> **s, T key, arena *perm)
{
    for (u64 h = hash(key); *s; h <<= 2) {
        if (key == (*s)->key) {
            return 0;
        }
        s = &(*s)->child[h>>62];
    }
    *s = back<set<T>>(perm);
    (*s)->key = key;
    return 1;
}

// Return the sum of the factors of x, excluding x, or -1 on overflow.
static i64 aliquot(i64 x)
{
    i64 sum = 1;
    for (i64 v = 2; v*v <= x; v++) {
        if (!(x % v)) {
            sum += (u64)v;
            if (sum < 1) return -1;  // overflow
            sum += (u64)(x/v==v ? 0 : x/v);
            if (sum < 1) return -1;  // overflow
        }
    }
    return sum;
}

template<typename T>
struct span {
    T *data = 0;
    iz len  = 0;

    span() = default;
    span(arena *perm, iz cap) : data(front<T>(cap, perm)), len{cap} {}
    i64 &operator[](iz i) { return data[i]; }
};

template<typename T>
static span<T> push(span<T> xs, T x, arena *perm)
{
    if ((byte *)(xs.data + xs.len) != perm->beg) {
        span<T> copy(perm, xs.len);
        for (iz i = 0; i < xs.len; i++) {
            copy[i] = xs[i];
        }
        xs = copy;
    }
    *front<T>(1, perm) = x;
    xs.len++;
    return xs;
}

template<>
u64 hash(i64 x) { return x * 1111111111111111111u; }

static span<i64> chain(i64 x, arena *perm)
{
    set<i64> *seen = 0;
    arena save = *perm;
    span<i64> r = push({}, x, perm);
    for (insert(&seen, x, perm);;) {
        x = aliquot(x);
        if (x < 0) {
            *perm = save;  // free all
            return {};     // overflow
        }
        r = push(r, x, perm);
        if (!insert(&seen, x, perm)) {
            perm->end = save.end;  // free set
            return r;
        }
    }
}

struct u8buf {
    u8 *buf;
    i32 len = 0;
    i32 cap;
    i32 fd;
    b32 err = 0;

    u8buf(i32 fd, arena *perm, i32 cap = 1<<12) :
        buf(back<u8>(cap, perm)), cap(cap), fd(fd) {}
};

static void flush(u8buf *b)
{
    if (!b->err && b->len) {
        b->err = !write(b->fd, b->buf, b->len);
        b->len = 0;
    }
}

static void print(u8buf *b, u8 *buf, iz len)
{
    for (iz off = 0; !b->err && off<len;) {
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

template<iz N>
static void print(u8buf *b, char const (&s)[N])
{
    print(b, (u8 *)s, N-1);
}

static void print(u8buf *b, i64 x)
{
    u8  buf[32];
    u8 *end = buf + 32;
    u8 *beg = end;
    i64 t = x<0 ? x : -x;
    do {
        *--beg = '0' - (u8)(t%10);
    } while (t /= 10);
    print(b, beg, end-beg);
}

static i32 run(arena scratch)
{
    enum { STDIN = 0, STDOUT = 1, STDERR = 2 };
    u8buf *stdout = back<u8buf>(&scratch, STDOUT, &scratch);

    for (i64 i = 1; i <= 10000; i++) {
        print(stdout, i);
        print(stdout, " ");
        flush(stdout);

        arena temp = scratch;
        span<i64> r = chain(i, &temp);

        if (!r.len) {
            print(stdout, "???\n");
        }
        for (iz i = 1; i < r.len; i++) {
            print(stdout, r[i]);
            if (i == r.len-1) {
                print(stdout, "\n");
            } else {
                print(stdout, " ");
            }
        }
    }

    flush(stdout);
    return stdout->err;
}


#if _WIN32
#define W32(r) extern "C" __declspec(dllimport) r __stdcall
W32(void)   ExitProcess(i32);
W32(uz)     GetStdHandle(i32);
W32(byte *) VirtualAlloc(uz, iz, i32, i32);
W32(b32)    WriteFile(uz, u8 *, i32, i32 *, uz);

static b32 write(i32 fd, u8 *buf, i32 len)
{
    uz h = GetStdHandle(-10 - fd);
    return WriteFile(h, buf, len, &len, 0);
}

static arena newarena(iz cap)
{
    arena r = {};
    r.beg = VirtualAlloc(0, cap, 0x3000, 4);
    r.end = r.beg + cap;
    return r;
}

extern "C" void mainCRTStartup(void)
{
    i32 r = run(newarena(1<<24));
    ExitProcess(r);
}
#endif
