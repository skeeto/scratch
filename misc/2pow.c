// Compute 2^1000000 with decimal output
// Porting note: Implement fullwrite(), call run() with 64MiB of memory.
// This is free and unencumbered software released into the public domain.
#include <stddef.h>

#define countof(a)  (i32)(sizeof(a) / sizeof((*a)))

typedef unsigned char u8;
typedef int           b32;
typedef int           i32;
typedef long long     i64;
typedef char          byte;
typedef ptrdiff_t     size;
typedef size_t        usize;

static b32 fullwrite(u8 *, i32);  // platform API

enum {
    BASE   = 1000000000,  // nine decimals per limb
    NUMCAP = 1<<16,       // capacity just over a half million decimals
};

typedef struct {
    i32 *digits;
    i32  len;
} num;

static num newnum(i32 **arena)
{
    num r = {0};
    r.digits = *arena;
    *arena += NUMCAP;
    return r;
}

static num set(num dst, i64 x)
{
    for (dst.len = 0; x; dst.len++, x/=BASE) {
        dst.digits[dst.len] = (i32)(x % BASE);
    }
    return dst;
}

static num copy(num dst, num src)
{
    for (i32 i = 0; i < src.len; i++) {
        dst.digits[i] = src.digits[i];
    }
    dst.len = src.len;
    return dst;
}

static num multiply(num dst, num a, num b)
{
    dst.len = a.len + b.len;
    for (i32 i = 0; i < dst.len; i++) {
        dst.digits[i] = 0;
    }

    for (i32 j = 0; j < a.len; j++) {
        i32 mc=0, ac=0, i=0;
        for (; i < b.len; i++) {
            i64 mr = (i64)a.digits[j]*b.digits[i] + mc;
            mc = (i32)(mr / BASE);
            i32 ar = dst.digits[i+j] + (i32)(mr%BASE) + ac;
            ac = ar / BASE;
            dst.digits[i+j] = ar % BASE;
        }
        for (ac += mc; ac; i++) {
            i32 ar = dst.digits[i+j] + ac;
            ac = ar / BASE;
            dst.digits[i+j] = ar % BASE;
        }
    }

    for (; dst.len && !dst.digits[dst.len-1]; dst.len--) {};
    return dst;
}

static num power(num dst, num n, i64 exponent, i32 *arena)
{
    num tmp = newnum(&arena);
    if (exponent == 0) {
        dst = set(dst, 1);
    } else if (exponent == 1) {
        dst = copy(dst, n);
    } else if (exponent%2 == 0) {
        tmp = multiply(tmp, n, n);
        dst = power(dst, tmp, exponent/2, arena);
    } else {
        dst = multiply(dst, n, n);
        tmp = power(tmp, dst, exponent/2, arena);
        dst = multiply(dst, n, tmp);
    }
    return dst;
}

typedef struct {
    u8  buf[1<<12];
    i32 len;
    b32 err;
} bufout;

static void flush(bufout *b)
{
    if (!b->err && b->len) {
        b->err = !fullwrite(b->buf, b->len);
        b->len = 0;
    }
}

static void print(bufout *b, u8 *buf, i32 len)
{
    u8 *end = buf + len;
    while (!b->err && buf<end) {
        i32 avail = countof(b->buf) - b->len;
        i32 count = avail<end-buf ? avail : (i32)(end-buf);
        u8 *dst = b->buf + b->len;
        for (i32 i = 0; i < count; i++) {
            dst[i] = buf[i];
        }
        buf += count;
        b->len += count;
        if (b->len == countof(b->buf)) {
            flush(b);
        }
    }
}

static void printnum(bufout *b, num n)
{
    for (i32 i = n.len-1; i >= 0; i--) {
        u8  buf[9] = "000000000";
        u8 *end = buf + countof(buf);
        u8 *beg = end;
        i32 x = n.digits[i];
        do {
            *--beg = '0' + (u8)(x%10);
        } while (x /= 10);
        beg = i==n.len-1 ? beg : buf;
        print(b, beg, (i32)(end-beg));
    }
}

static b32 run(byte *heap)
{
    bufout *out = (bufout *)heap;
    out->err = out->len = 0;

    i32 *arena = (i32 *)(heap + sizeof(*out));

    num two = set(newnum(&arena), 2);
    num dst = newnum(&arena);
    dst = power(dst, two, 1000000, arena);

    printnum(out, dst);
    print(out, (u8 *)"\n", 1);
    flush(out);
    return !out->err;
}


#if _WIN32
// $ cc -nostartfiles -fno-builtin -O3 -o 2pow.exe 2pow.c
// $ cl /O2 2pow.c /link /subsystem:console kernel32.lib
#define W32(r) __declspec(dllimport) r __stdcall
W32(void)   ExitProcess(i32);
W32(void *) GetStdHandle(i32);
W32(void *) VirtualAlloc(void *, usize, i32, i32);
W32(b32)    WriteFile(void *, u8 *, i32, i32 *, void *);

static b32 fullwrite(u8 *buf, i32 len)
{
    return WriteFile(GetStdHandle(-11), buf, len, &len, 0);
}

#if __i386__
__attribute((force_align_arg_pointer))
#endif
void mainCRTStartup(void)
{
    byte *heap = VirtualAlloc(0, 1<<26, 0x3000, 4);
    b32 err = !run(heap);
    ExitProcess(err);
}


#else  // !_WIN32
// $ cc -O3 -o 2pow 2pow.c
void *malloc(usize);
size  write(i32, void *, usize);

static b32 fullwrite(u8 *buf, i32 len)
{
    for (i32 off = 0; off < len;) {
        i32 r = (i32)write(1, buf+off, len-off);
        if (r < 1) {
            return 0;
        }
        off += r;
    }
    return 1;
}

int main(void)
{
    return !run(malloc(1<<26));
}
#endif
