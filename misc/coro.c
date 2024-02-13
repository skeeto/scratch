// Coroutines from a bit of assembly
//
// The interface is a struct (coro) and a function (yield). Coroutines
// pass values between each other through yield. The first value is
// passed as the argument to the coroutine function, and the rest are
// returned from yield(). Coroutine functions must not return.
//
// This is free and unencumbered software released into the public domain.

// x64 coroutine implementation

typedef struct {
    void *rip;
    void *rsp;
    void *reg[8];
    void *xmm[4];
} coro;

__attribute((naked))
static void *yield(coro *c, void *arg)
{
    asm (
        "pop    %r10\n"             // pop the return pointer
        "xchg   %r10,   0(%rcx)\n"  // ..and store it as old rip
        "xchg   %rsp,   8(%rcx)\n"  // swap stacks
        "xchg   %rbp,  16(%rcx)\n"  // preserve register
        "xchg   %rbx,  24(%rcx)\n"  // "
        "xchg   %rdi,  32(%rcx)\n"  // "
        "xchg   %rsi,  40(%rcx)\n"  // "
        "xchg   %r12,  48(%rcx)\n"  // "
        "xchg   %r13,  56(%rcx)\n"  // "
        "xchg   %r14,  64(%rcx)\n"  // "
        "xchg   %r15,  72(%rcx)\n"  // "
        "movups %xmm6, 80(%rcx)\n"  // "
        "movups %xmm7, 96(%rcx)\n"  // "
        "mov    %rdx,  %rcx\n"      // pass arg as first argument
        "mov    %rdx,  %rax\n"      // ...also as the return value
        "jmp   *%r10\n"             // switch to other coroutine
    );
}


// Demo (w64devkit)
// $ cc -nostdlib -o coro.exe coro.c -lkernel32 -lmemory
//
// Assemble yield() separately and this demo also works with MSVC:
// $ as -o yield.obj yield.s
// $ cl /GS- coro.c yield.obj /link /subsystem:console /nodefaultlib kernel32.lib
//
// NOTE: Coroutine stacks are incompatible with chkstk probes, so it's
// critical that none are used. The above commands will fail to link if
// that occurs. Further, coroutines must not call external functions
// that might use chkstk probes. This probably includes kernel32.dll,
// but the "print" function breaks that rule.

#define assert(c)     while (!(c)) *(volatile int *)0 = 0
#define countof(a)    (size)(sizeof(a) / sizeof(*(a)))
#define new(a, t, n)  (t *)alloc(a, sizeof(t), _Alignof(t), n)

typedef unsigned char      u8;
typedef   signed int       i32;
typedef   signed long long i64;
typedef unsigned long long u64;
typedef   signed long long size;
typedef   signed long long iptr;
typedef unsigned long long uptr;

#define W32(r) __declspec(dllimport) r __stdcall
W32(void)   ExitProcess(i32);
W32(iptr)   GetStdHandle(i32);
W32(void *) VirtualAlloc(uptr, size, i32, i32);
W32(i32)    WriteFile(iptr, void *, i32, i32 *, uptr);

typedef struct {
    char *beg;
    char *end;
} arena;

static void *alloc(arena *a, size objsize, size align, size count)
{
    size padding = (uptr)a->end & (align - 1);
    assert(count <= (a->end - a->beg - padding)/objsize);
    size total = objsize * count;
    char *r = a->end -= total + padding;
    for (size i = 0; i < total; i++) {
        r[i] = 0;
    }
    return r;
}

static coro *newcoro(arena *perm, void corofunc(void *))
{
    coro *c = new(perm, coro, 1);
    size cap = 1<<14;  // small coro stacks
    c->rsp = (char *)alloc(perm, 16, 16, cap/16) + cap - 40;
    c->rip = (void *)corofunc;
    return c;
}

typedef struct {
    iptr fd;
    u8  *buf;
    i32  len;
} message;

// Print each message passed to the coroutine. Pass the return coroutine
// for the first call.
static void print(void *arg)
{
    coro *ret = arg;
    for (;;) {
        message *m = yield(ret, 0);
        WriteFile(m->fd, m->buf, m->len, &m->len, 0);
    }
}

// Test the print coroutine function by printing two strings.
static void simpleprint(arena scratch)
{
    coro *c = newcoro(&scratch, print);
    yield(c, c);  // prime the printer
    iptr stdout = GetStdHandle(-11);
    static u8 hello[] = "Hello, ";
    static u8 world[] = "world!\n";
    yield(c, &(message){stdout, hello, countof(hello)-1});
    yield(c, &(message){stdout, world, countof(world)-1});
}

// Generate random 64-bit integers. Pass the return coroutine in the
// first call, which also seeds the generator. Each yield returns a u64
// pointer to the next result.
static void rand64(void *arg)
{
    coro *ret = arg;
    for (u64 rng = (u64)(uptr)ret;;) {
        rng = rng*0x3243f6a8885a308d + 1;
        u64 r = rng;
        r ^= r >> 32;
        r *= 1111111111111111111u;
        r ^= r >> 32;
        yield(ret, &r);
    }
}

// Endlessly print outputs from the rand64 coroutine function. Uses two
// coroutines simultaneously.
static void randprint(arena scratch)
{
    coro *prtcoro = newcoro(&scratch, print);
    yield(prtcoro, prtcoro);  // prime the printer
    message msg = {0};
    msg.fd  = GetStdHandle(-12);
    msg.buf = (u8[]){"................\n"};
    msg.len = 17;
    for (coro *rng = newcoro(&scratch, rand64);;) {
        u64 r = *(u64 *)yield(rng, rng);
        for (i32 i = 0; i < 16; i++) {
            msg.buf[i] = "0123456789abcdef"[(r>>(60-i*4))&15];
        }
        yield(prtcoro, &msg);
    }
}

typedef struct {
    i64   lo;
    i64   hi;
    coro *ret;
} rangectx;

// Generate 64-bit integers in [lo, hi). Pass a rangectx in the first
// call to configure it. Each yield returns a i64 pointer to the next
// value. Returns null on completion.
static void range(void *arg)
{
    rangectx *ctx = arg;
    for (i64 i = ctx->lo; i < ctx->hi; i++) {
        yield(ctx->ret, &i);
    }
    yield(ctx->ret, 0);
}

// Test the range generator by printing some numbers. Uses two
// coroutines simultaneously.
static void rangetest(arena scratch)
{
    message msg = {0};
    msg.fd = GetStdHandle(-11);
    coro *prtcoro = newcoro(&scratch, print);
    yield(prtcoro, prtcoro);  // prime the printer

    coro *rngcoro = newcoro(&scratch, range);
    rangectx rng = {1000, 1015, rngcoro};
    for (i64 *r = yield(rngcoro, &rng); r; r = yield(rngcoro, 0)) {
        u8  buf[32];
        u8 *end = buf + countof(buf);
        u8 *beg = end;
        *--beg = '\n';
        i64 x = *r;
        do {
            *--beg = (u8)(x%10) + '0';
        } while (x /= 10);
        *--beg = '=';
        *--beg = 'i';
        msg.buf = beg;
        msg.len = (i32)(end - beg);
        yield(prtcoro, &msg);
    }
}

void mainCRTStartup(void)
{
    size cap = 1<<24;
    arena scratch = {0};
    scratch.beg = VirtualAlloc(0, cap, 0x3000, 4);
    scratch.end = scratch.beg + cap;

    #if 0
    randprint(scratch);  // endless loop
    #else
    simpleprint(scratch);
    rangetest(scratch);
    #endif
    ExitProcess(0);
}
