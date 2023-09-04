// Arena-backed, generic slices (experiment)
//
// The main feature is the type-generic push() macro with supporting
// grow_() function. It allocates out of a simple arena with non-local
// goto for out-of-memory errors. On resize, the old buffer is left in
// place and continues to be a valid copy so long as its arena keeps it
// alive. Elements are zero-initialized when newly-allocated. The push
// macro evalutes to a pointer to the newly-pushed element. Callers
// define a (data, len, cap) struct, and grow_ operates on it by
// memcpy-based type punning.
//
//   struct struct {
//       item *data;
//       size  len;
//       size  cap;
//   } itemslice;
//
//   itemslice items = {};                 // empty slice
//   *push(arena, &items) = (item){...};   // append and assign
//   item *item = push(arena, &items);     // append and retrieve
//   item->name = ...;                     // "
//   items.len = 0;                        // truncate the slice
//
// The push() result can be passed straight to contructors:
//
//   void item_init(item *, ...);          // "constructor" prototype
//   init_item(push(arena, &items), ...);  // like "placement new"
//
// Because of the non-local goto in the arena, there is no need to check
// for errors. The push() macro simply will not return, and control will
// go to the out-of-memory "handler" which can reset the arena pointer
// to free all allocations, e.g. to recover and keep going after OOM.
//
// Due to the use of typeof, _Alignof, and statement declaration, this
// program requires GNU C and probably only works with GCC and Clang. It
// also includes a bunch of new little tricks I've learned (circa August
// 2023).
//
// This is free and unencumbered software released into the public domain.

typedef unsigned char      byte;
typedef __PTRDIFF_TYPE__   size;
typedef __UINT8_TYPE__     u8;
typedef unsigned short     u16;
typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef unsigned long long u64;

#define sizeof(x)   (size)sizeof(x)
#define alignof(x)  (size)_Alignof(x)
#define countof(a)  (sizeof(a) / sizeof(*(a)))
#define lengthof(s) (countof(s) - 1)
#define assert(c)   while (!(c)) __builtin_unreachable()

static b32 fullwrite(i32, u8 *, size);

// Memory

#define new(...)              newx(__VA_ARGS__, new3, new2)(__VA_ARGS__)
#define newx(a, b, c, d, ...) d
#define new2(a, t)            (t *)alloc(a, sizeof(t), alignof(t), 1)
#define new3(a, t, n)         (t *)alloc(a, sizeof(t), alignof(t), n)

static byte *copy(byte *dst, byte *src, size len)
{
    for (size i = 0; i < len; i++) {
        dst[i] = src[i];
    }
    return dst + len;
}

typedef struct {
    byte *mem;
    size  cap;
    size  off;
    void *oom[5];
} arena;

static arena *newarena(byte *heap, size len)
{
    assert(len > sizeof(arena));
    arena *a = (arena *)heap;
    a->mem = heap;
    a->cap = len;
    a->off = sizeof(arena);
    return a;
}

__attribute((malloc, alloc_size(2, 4), alloc_align(3)))
static byte *alloc(arena *a, size objsize, size align, size count)
{
    size avail = a->cap - a->off;
    size pad = -a->off & (align - 1);
    if (count > (avail - pad)/objsize) {
        __builtin_longjmp(a->oom, 1);
    }
    size total = count * objsize;
    byte *p = a->mem + a->off + pad;
    for (size i = 0; i < total; i++) {
        p[i] = 0;
    }
    a->off += pad + total;
    return p;
}

// Generic slices

// A slice is a (data, len, cap) typed (pointer, size, size). The macro
// evaluates to a pointer to the newly-pushed element. Arguments are
// evaluated exactly once and may safely have side effects.
#define push(arena, sliceptr) ({ \
    typeof(arena) a_ = (arena); \
    typeof(sliceptr) s_ = (sliceptr); \
    if (s_->len >= s_->cap) { \
        grow_(a_, (byte *)s_, sizeof(*s_->data), alignof(*s_->data)); \
    } \
    s_->data + s_->len++; \
})

// Double the capacity of a (data, len, cap) slice.
static void grow_(arena *a, byte *header, size objsize, size align)
{
    struct {
        byte *data;
        size  len;
        size  cap;
    } replica;
    copy((byte *)&replica, header, sizeof(replica));
    assert(replica.cap >= 0);
    assert(replica.len >= 0);
    assert(replica.len <= replica.cap);

    if (!replica.cap) {
        replica.cap = 1;
    }
    byte *data = alloc(a, objsize*2, align, replica.cap);
    copy(data, replica.data, objsize*replica.len);

    replica.data = data;
    replica.cap *= 2;
    copy(header, (byte *)&replica, sizeof(replica));
}

// Test program

typedef struct {
    u8   *buf;
    size  cap;
    size  len;
    b32   err;
} bout;

static void flush(bout *o)
{
    if (!o->err && o->len) {
        o->err = !fullwrite(1, o->buf, o->len);
        o->len = 0;
    }
}

static void write(bout *o, u8 *buf, size len)
{
    u8 *end = buf + len;
    while (!o->err && buf<end) {
        size avail = o->cap - o->len;
        size count = avail<end-buf ? avail : end-buf;
        copy(o->buf+o->len, buf, count);
        buf += count;
        o->len += count;
        if (o->len == o->cap) {
            flush(o);
        }
    }
}

static void print(bout *o, i32 x, size width)
{
    u8 buf[32];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    i32 t = x<0 ? x : -x;
    do {
        *--beg = '0' - (u8)(t % 10);
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    for (size i = 0; i < width - (end - beg); i++) {
        write(o, (u8 *)" ", 1);
    }
    write(o, beg, end-beg);
}

static i32 rand31(u64 *rng)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return (i32)(*rng >> 33);
}

static u64 *newrng(arena *a)
{
    size seed;
    asm volatile ("rdrand %0" : "=r"(seed));
    u64 *rng = new(a, u64);
    *rng = seed;
    return rng;
}

typedef struct {
    i32 *data;
    size len;
    size cap;
} i32slice;

static u32 run(byte *heap, size heaplen)
{
    arena *a = newarena(heap, heaplen);
    if (__builtin_setjmp(a->oom)) {
        static u8 msg[] = "out of memory\n";
        fullwrite(2, msg, lengthof(msg));
        return 2;
    }

    bout *stdout = new(a, bout);
    stdout->cap = 1<<12;
    stdout->buf = new(a, u8, stdout->cap);

    i32 nbins = 100;
    i32slice *bins = new(a, i32slice, nbins);
    u64 *rng = newrng(a);

    for (i32 i = 0; i < 1000; i++) {
        i32 v = rand31(rng) % 1000;
        *push(a, bins + v%nbins) = v;
    }

    for (i32 b = 0; b < nbins; b++) {
        print(stdout, b, 2);
        write(stdout, (u8 *)": ", 2);
        for (size i = 0; i < bins[b].len; i++) {
            print(stdout, bins[b].data[i], 3);
            write(stdout, (u8 *)" ", 1);
        }
        write(stdout, (u8 *)"\n", 1);
    }

    flush(stdout);
    return stdout->err;
}


#if _WIN32
// $ cc -nostartfiles -fno-builtin -o slice slice.c
// $ ./slice

typedef struct {} *handle;

#define W32 __attribute((dllimport, stdcall))
W32 void   ExitProcess(u32) __attribute((noreturn));
W32 handle GetStdHandle(u32);
W32 b32    WriteFile(handle, u8 *, u32, u32 *, void *);

static b32 fullwrite(i32 fd, u8 *buf, size len)
{
    assert((size)(u32)len == len);
    handle out = GetStdHandle(-10 - fd);
    u32 dummy;
    return WriteFile(out, buf, (u32)len, &dummy, 0);
}

__attribute((force_align_arg_pointer))
void mainCRTStartup(void)
{
    static byte memory[1<<24] __attribute((aligned(64)));
    byte *heap = memory;
    asm ("" : "+r"(heap));  // launder the heap pointer
    u32 r = run(heap, countof(memory));
    ExitProcess(r);
}


#elif __linux
// $ cc -nostdlib -fno-builtin -o slice slice.c
// $ ./slice

static b32 fullwrite(i32 fd, u8 *buf, size len)
{
    for (size off = 0; off < len;) {
        size r;
        asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(1), "D"(fd), "S"(buf+off), "d"(len-off)
            : "rcx", "r11", "memory"
        );
        if (r < 1) {
            return 0;
        }
        off += r;
    }
    return 1;
}

__attribute((force_align_arg_pointer))
void _start(void)
{
    static byte memory[1<<24] __attribute((aligned(64)));
    byte *heap = memory;
    asm ("" : "+r"(heap));  // launder the heap pointer
    u32 r = run(heap, countof(memory));
    asm volatile ("syscall" : : "a"(60), "D"(r));
}
#endif
