// Summarize a numeric sequence on standard input with live updates
//
// Linux:     $ cc -O3 -o summarize summarize.c
// Mingw-w64: $ cc -O3 -nostartfiles -o summarize.exe summarize.c
// MSVC:      $ cl /O2 /GS- summarize.c
//
// Example:   $ while true; do echo $RANDOM; done | ./summarize
//
// TODO: argument parsing, command line options
// Ref: https://github.com/ahmedakef/summarize
// This is free and unencumbered software released into the public domain.

// Fundamental definitions
#include <stddef.h>

#ifdef DEBUG
  #define ASSERT(c) if (!(c)) *(volatile int *)0 = 0
#else
  #define ASSERT(c) (void)sizeof(c)
#endif

typedef int Bool;
typedef long long I64;
typedef ptrdiff_t Size;
typedef unsigned char Byte;
#define SIZEOF(expr) ((Size)sizeof(expr))

#ifdef _MSC_VER
  #pragma intrinsic(_InterlockedIncrement)
  #define __atomic_fetch_add(p, a, c) (_InterlockedIncrement((long *)p) - a)
  #define __atomic_load_n(p, c) (*(volatile int *)p)
  #define __atomic_store_n(p, a, c) (*(volatile int *)p = a)
#endif


// Platform

static Size platform_read(int, Byte *, Size);   // like read(2)
static Bool platform_write(int, Byte *, Size);  // like write(2)
static Bool platform_wait(int *, int, int ms);  // futex wait
static void platform_wake(int *);               // futex wake


// Application

enum {
    Arena_ZERO = 1<<0,
};

typedef struct {
    Size cap;
    Size off;
} Arena;

static Arena *newarena(Byte *heap, Size cap)
{
    ASSERT(cap > SIZEOF(Arena));
    Arena *arena = (Arena *)heap;
    arena->cap = cap;
    arena->off = SIZEOF(Arena);
    return arena;
}

#define NEW(arena, type) (type *)alloc(arena, SIZEOF(type), Arena_ZERO)
static Byte *alloc(Arena *arena, Size size, int flags)
{
    Size avail = arena->cap - arena->off;
    ASSERT(avail > size);
    volatile Byte *p = (Byte *)arena + arena->off;
    if (flags & Arena_ZERO) {
        for (Size i = 0; i < size; i++) {
            p[i] = 0;
        }
    }
    arena->off += size;
    return (Byte *)p;
}

static Bool whitespace(Byte b)
{
    return b=='\t' || b=='\n' || b=='\r' || b==' ';
}

static Bool digit(Byte b)
{
    return b>='0' && b<='9';
}

typedef enum {
    ParserState_INVALID    = -2,
    ParserState_SIGNED     = -1,
    ParserState_INIT       = +0,
    ParserState_INTEGRAL   = +1,
    ParserState_FRACTIONAL = +2,
    ParserState_DONE       = +3,
} ParserState;

enum {
    ParserState_MINUS_FLAG  = 1<<0,
    ParserState_DIGITS_FLAG = 1<<1,
};

typedef struct {
    double accum;
    double divisor;
    int flags;
    ParserState state;
} DoubleParser;

static void parsedouble(DoubleParser *p, Byte b)
{
    switch (p->state) {
    case ParserState_INVALID:
        if (b == '\n') {
            p->state = ParserState_INIT;
        }
        break;

    case ParserState_INIT:
        if (digit(b)) {
            p->accum = b - '0';
            p->flags = ParserState_DIGITS_FLAG;
            p->state = ParserState_INTEGRAL;
        } else if (b == '-') {
            p->accum = 0;
            p->flags = ParserState_MINUS_FLAG;
            p->state = ParserState_SIGNED;
        } else if (b == '+') {
            p->accum = 0;
            p->flags = 0;
            p->state = ParserState_SIGNED;
        } else if (b == '.') {
            p->accum = 0;
            p->divisor = 10;
            p->flags = 0;
            p->state = ParserState_FRACTIONAL;
        } else if (!whitespace(b)) {
            p->state = ParserState_INVALID;
        }
        break;

    case ParserState_SIGNED:
        if (digit(b)) {
            p->accum = b - '0';
            p->flags |= ParserState_DIGITS_FLAG;
            p->state = ParserState_INTEGRAL;
        } else if (b == '.') {
            p->divisor = 10;
            p->state = ParserState_FRACTIONAL;
        } else if (b == '\n') {
            p->state = ParserState_INIT;
        } else {
            p->state = ParserState_INVALID;
        }
        break;

    case ParserState_INTEGRAL:
        if (digit(b)) {
            p->accum = p->accum*10 + (b - '0');
            p->flags |= ParserState_DIGITS_FLAG;
        } else if (b == '.') {
            p->divisor = 10;
            p->state = ParserState_FRACTIONAL;
        } else if (b == '\n') {
            p->state = ParserState_INIT;
        } else if (whitespace(b)) {
            p->state = ParserState_DONE;
        } else {
            p->state = ParserState_INVALID;
        }
        break;

    case ParserState_FRACTIONAL:
        if (digit(b)) {
            p->accum += (b - '0')/p->divisor;
            p->divisor *= 10;
            p->flags |= ParserState_DIGITS_FLAG;
        } else if (b == '\n') {
            p->state = ParserState_INIT;
        } else if (whitespace(b)) {
            p->state = ParserState_DONE;
        } else {
            p->state = ParserState_INVALID;
        }
        break;

    case ParserState_DONE:
        if (b == '\n') {
            p->state = ParserState_INIT;
        } else if (!whitespace(b)) {
            p->state = ParserState_INVALID;
        }
        break;
    }
}

typedef struct {
    double result;
    Bool ok;
} ParserResult;

static ParserResult parserfinish(DoubleParser *p)
{
    ParserResult r;
    r.result = p->accum * (p->flags&ParserState_MINUS_FLAG ? -1 : +1);
    r.ok = p->state>0 && (p->flags&ParserState_DIGITS_FLAG);
    return r;
}

typedef struct {
    Byte *buf;
    int cap;
    int len;
    int fd;
    Bool error;
} Output;

static Output *newoutput(Arena *arena, int fd)
{
    Output *output = NEW(arena, Output);
    output->fd = fd;
    output->cap = 1<<12;
    output->buf = alloc(arena, output->cap, 0);
    return output;
}

static void flush(Output *output)
{
    if (!output->error && output->len) {
        output->error |= !platform_write(output->fd, output->buf, output->len);
        output->len = 0;
    }
}

#define APPEND_STR(output, s) append(output, (Byte *)s, SIZEOF(s)-1)
static Size append(Output *output, Byte *buf, Size len)
{
    Byte *end = buf + len;
    while (buf<end && !output->error) {
        Size left = end - buf;
        int avail = output->cap - output->len;
        int count = left<avail ? (int)left : avail;
        Byte *dst = output->buf + output->len;
        for (int i = 0; i < count; i++) {
            dst[i] = buf[i];
        }
        output->len += count;
        buf += count;
        if (output->len == output->cap) {
            flush(output);
        }
    }
    return len;
}

static Size append_byte(Output *output, Byte b)
{
    return append(output, &b, 1);
}

static Size append_i64(Output *output, I64 x)
{
    Byte tmp[32];
    Byte *end = tmp + SIZEOF(tmp);
    Byte *beg = end;
    I64 t = x>0 ? -x : x;
    do {
        *--beg = '0' - (Byte)(t%10);
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    return append(output, beg, end-beg);
}

static Size append_double(Output *output, double x)
{
    Size len = 0;
    if (x < 0) {
        len += append_byte(output, '-');
        x = -x;
    }

    I64 prec = 1000;  // i.e. 3 decimals
    x += 0.5 / (double)prec;  // round last decimal
    I64 integral = (I64)x;
    I64 fractional = (I64)((x - (double)integral)*(double)prec);
    if (fractional < 0) {
        len += APPEND_STR(output, "inf");
    } else {
        len += append_i64(output, integral);
        if (fractional) {
            len += append_byte(output, '.');
            for (I64 i = prec/10; i > 1; i /= 10) {
                if (i > fractional) {
                    len += append_byte(output, '0');
                }
            }
            len += append_i64(output, fractional);
        }
    }
    return len;
}

static Size append_pad(Output *output, Size amount)
{
    Size len = 0;
    do {
        len += append_byte(output, ' ');
    } while (--amount > 0);
    return len;
}

typedef struct {
    double sum, err;
} Kahan;

static Kahan sum(Kahan k, double x)
{
    double y = x - k.err;
    double t = k.sum + y;
    k.err = t - k.sum - y;
    k.sum = t;
    return k;
}

// Jain, Raj, Chlamtac. "The P^2 Algorithm for Dynamic Calculation of
// Quantiles and Histograms Without Storing Observations." (1985)
typedef struct {
    double markers[5];
    double desired[5];
    double increment[5];
    double positions[5];
} Psquare;

static Psquare psquare(double p)
{
    Psquare ps;
    ps.markers[0] = 0;
    ps.markers[1] = 0;
    ps.markers[2] = 0;
    ps.markers[3] = 0;
    ps.markers[4] = 0;
    ps.desired[0] = 1;
    ps.desired[1] = 1 + 2*p;
    ps.desired[2] = 1 + 4*p;
    ps.desired[3] = 3 + 2*p;
    ps.desired[4] = 5;
    ps.increment[0] = 0;
    ps.increment[1] = p/2;
    ps.increment[2] = p;
    ps.increment[3] = (1 + p)/2;
    ps.increment[4] = 1;
    ps.positions[0] = 1;
    ps.positions[1] = 2;
    ps.positions[2] = 3;
    ps.positions[3] = 4;
    ps.positions[4] = 5;
    return ps;
}

static void insert(Psquare *ps, double x, I64 idx)
{
    if (idx < 5) {
        int n = (int)idx;
        for (int i = 0; i < n; i++) {
            if (ps->markers[i] > x) {
                double tmp = ps->markers[i];
                ps->markers[i] = x;
                x = tmp;
            }
        }
        ps->markers[n] = x;

    } else {
        int k;
        if (x < ps->markers[0]) {
            k = 0;
            ps->markers[0] = x;
        } else if (x > ps->markers[4]) {
            k = 3;
            ps->markers[4] = x;
        } else {
            for (k = 0; k < 3; k++) {
                if (x < ps->markers[k+1]) {
                    break;
                }
            }
        }

        for (int i = k+1; i < 5; i++) {
            ps->positions[i] += 1.0;
        }

        for (int i = 0; i < 5; i++) {
            ps->desired[i] += ps->increment[i];
        }

        for (int i = 1; i <= 3; i++) {
            double d = ps->desired[i] - ps->positions[i];
            double ip = ps->positions[i-1];
            double ii = ps->positions[ i ];
            double in = ps->positions[i+1];
            if ((d>=1 && in-ii>1) || (d<=-1 && ip-ii<-1)) {
                int di = d<0 ? -1 : +1;
                double dd = di;
                double qp = ps->markers[i-1];
                double q  = ps->markers[ i ];
                double qn = ps->markers[i+1];
                double qq = q + dd/(in - ip) * ((ii-ip+dd)*(qn-q)/(in-ii) +
                                                (in-ii-dd)*(q-qp)/(ii-ip));
                if (qp<qq && qq<qn) {
                    ps->markers[i] = qq;
                } else {
                    double qd = ps->markers[i+di];
                    double id = ps->positions[i+di];
                    q += dd*(qd-q)/(id-ii);
                    ps->markers[i] = q;
                }
                ps->positions[i] += dd;
            }
        }
    }
}

typedef struct {
    I64 count;
    double min, max;
    Kahan kahan;
    Psquare p95;
    Psquare p99;
} Accumulator;

static Accumulator *newaccumulator(Arena *arena)
{
    Accumulator *acc = NEW(arena, Accumulator);
    acc->min = +1.7976931348623157e+308;
    acc->max = -1.7976931348623157e+308;
    acc->p95 = psquare(0.95);
    acc->p99 = psquare(0.99);
    return acc;
}

static void accumulate(Accumulator *acc, double x)
{
    acc->kahan = sum(acc->kahan, x);
    acc->min = x<acc->min ? x : acc->min;
    acc->max = x>acc->max ? x : acc->max;
    insert(&acc->p95, x, acc->count);
    insert(&acc->p99, x, acc->count);
    acc->count++;
}

static void printheader(Output *output, int width)
{
    append_pad(output, width - APPEND_STR(output, "Count"));
    append_pad(output, width - APPEND_STR(output, "Mean"));
    append_pad(output, width - APPEND_STR(output, "Min"));
    append_pad(output, width - APPEND_STR(output, "Max"));
    append_pad(output, width - APPEND_STR(output, "P95"));
    append_pad(output, width - APPEND_STR(output, "P99"));
    append_byte(output, '\n');
}

static void printstats(Output *output, Accumulator *acc, int width)
{
    append_pad(output, width - append_i64(output, acc->count));
    if (acc->count >= 1) {
        double mean = acc->kahan.sum / (double)acc->count;
        append_pad(output, width - append_double(output, mean));
        append_pad(output, width - append_double(output, acc->min));
        append_pad(output, width - append_double(output, acc->max));
    } else {
        append_pad(output, width - APPEND_STR(output, "N/A"));
        append_pad(output, width - APPEND_STR(output, "N/A"));
        append_pad(output, width - APPEND_STR(output, "N/A"));
    }
    if (acc->count >= 5) {
        double p95 = acc->p95.markers[2];
        double p99 = acc->p99.markers[2];
        append_pad(output, width - append_double(output, p95));
        append_pad(output, width - append_double(output, p99));
    } else {
        append_pad(output, width - APPEND_STR(output, "N/A"));
        append_pad(output, width - APPEND_STR(output, "N/A"));
    }
    append_byte(output, '\n');
}

typedef struct {
    Byte *buf;
    Size cap;
    Size len;
    Size off;
    Bool eof;
} Input;

static Input *newinput(Arena *arena)
{
    Input *input = NEW(arena, Input);
    input->cap = 1<<14;
    input->buf = alloc(arena, input->cap, 0);
    return input;
}

static Byte nextbyte(Input *in)
{
    if (!in->eof && in->len==in->off) {
        in->off = 0;
        in->len = platform_read(0, in->buf, in->cap);
        in->eof = in->len == 0;
    }
    return in->eof ? 0 : in->buf[in->off++];
}

typedef struct {
    int tickets;
    int current;
} Mutex;

static void lock(Mutex *m)
{
    int ticket = __atomic_fetch_add(&m->tickets, 1, __ATOMIC_RELAXED);
    for (;;) {
        int current = __atomic_load_n(&m->current, __ATOMIC_ACQUIRE);
        if (ticket == current) {
            break;
        }
    }
}

static void unlock(Mutex *m)
{
    __atomic_fetch_add(&m->current, 1, __ATOMIC_RELEASE);
}

typedef struct {
    Accumulator *acc;
    Input *stdin;
    Output *stdout;
    int field_width;
    int delay_ms;
    Mutex mutex;
    int done;
} Context;

// Initialize an application context in the provided heap and return its
// pointer. The context pointer will be passed to the main and worker
// threads. Returns a null pointer on failure.
static void *summarize_init(Byte *heap, Size len)
{
    Arena *arena = newarena(heap, len);
    Context *ctx = NEW(arena, Context);
    ctx->acc = newaccumulator(arena);
    ctx->stdin = newinput(arena);
    ctx->stdout = newoutput(arena, 1);
    ctx->field_width = 13;
    ctx->delay_ms = 1000;
    return ctx;
}

// The application worker thread, given the context returned by init.
static void summarize_thread(void *arg)
{
    Context *ctx = arg;
    Accumulator *acc = ctx->acc;
    Input *stdin = ctx->stdin;

    DoubleParser p = {0};
    do {
        Byte c = nextbyte(stdin);
        if (c=='\n' || stdin->eof) {
            ParserResult r = parserfinish(&p);
            if (r.ok) {
                lock(&ctx->mutex);
                accumulate(acc, r.result);
                unlock(&ctx->mutex);
            }
        }
        parsedouble(&p, (Byte)c);
    } while (!stdin->eof);

    __atomic_store_n(&ctx->done, 1, __ATOMIC_SEQ_CST);
    platform_wake(&ctx->done);
}

// The application main thread, given the context returned by init. The
// return value is the exit status.
static int summarize_main(void *arg)
{
    Context *ctx = arg;
    Accumulator *acc = ctx->acc;
    Output *stdout = ctx->stdout;

    printheader(stdout, ctx->field_width);
    while (!platform_wait(&ctx->done, 0, ctx->delay_ms)) {
        lock(&ctx->mutex);
        printstats(stdout, acc, ctx->field_width);
        unlock(&ctx->mutex);
        flush(stdout);
    }

    printstats(stdout, acc, ctx->field_width);
    flush(stdout);
    return stdout->error;
}


#ifdef _WIN32
// Windows platform

#ifdef _MSC_VER
  #pragma comment(lib, "kernel32.lib")
  #pragma comment(linker, "/subsystem:console")
#endif

#if __i686__
  #define ENTRYPOINT __attribute((force_align_arg_pointer))
#else
  #define ENTRYPOINT
#endif

typedef int BOOL;
typedef unsigned DWORD;
typedef ptrdiff_t HANDLE;
typedef DWORD (__stdcall *THRFUN)(void *);

__declspec(dllimport)
void *__stdcall VirtualAlloc(void *, size_t, DWORD, DWORD);
__declspec(dllimport)
void __stdcall ExitProcess(unsigned);

__declspec(dllimport)
HANDLE __stdcall GetStdHandle(int);
__declspec(dllimport)
BOOL __stdcall ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
__declspec(dllimport)
BOOL __stdcall WriteFile(HANDLE, void *, DWORD, DWORD *, void *);

__declspec(dllimport)
HANDLE __stdcall LoadLibraryA(char *);
__declspec(dllimport)
void *__stdcall GetProcAddress(HANDLE, char *);

__declspec(dllimport)
HANDLE __stdcall CreateThread(void *, size_t, THRFUN, void *, DWORD, DWORD *);
__declspec(dllimport)
void __stdcall Sleep(DWORD);

static Bool platform_write(int fd, Byte *buf, Size len)
{
    ASSERT(len <= 0xffffffff);
    HANDLE h = GetStdHandle(-10 - fd);
    DWORD n;
    return WriteFile(h, buf, (DWORD)len, &n, 0) && n==(DWORD)len;
}

static Size platform_read(int fd, Byte *buf, Size len)
{
    ASSERT(len <= 0xffffffff);
    HANDLE h = GetStdHandle(-10 - fd);
    DWORD n;
    return ReadFile(h, buf, (DWORD)len, &n, 0) ? n : 0;
}

static int (__stdcall *nt_RtlWaitOnAddress)(void *, void *, size_t, void *);
static int (__stdcall *nt_RtlWakeAddressAll)(void *);

static Bool platform_wait(int *p, int expect, int ms)
{
    if (nt_RtlWaitOnAddress && nt_RtlWakeAddressAll) {
        I64 timeout = ms * -10000LL;
        return !nt_RtlWaitOnAddress(p, &expect, 4, &timeout);
    } else {
        Sleep(ms);
        return __atomic_load_n(p, __ATOMIC_SEQ_CST);
    }
}

static void platform_wake(int *p)
{
    if (nt_RtlWaitOnAddress) {
        nt_RtlWakeAddressAll(p);
    }
}

ENTRYPOINT
static DWORD __stdcall win32_thread(void *arg)
{
    summarize_thread(arg);
    return 0;
}

ENTRYPOINT
void mainCRTStartup(void)
{
    HANDLE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll) {
        nt_RtlWaitOnAddress = GetProcAddress(ntdll, "RtlWaitOnAddress");
        nt_RtlWakeAddressAll = GetProcAddress(ntdll, "RtlWakeAddressAll");
    }

    Size heapsize = 1<<21;
    Byte *heap = VirtualAlloc(0, heapsize, 0x3000, 4);
    void *p = summarize_init(heap, heapsize);
    int status = !!p;
    if (p) {
        HANDLE thread = CreateThread(0, 0, win32_thread, p, 0, 0);
        status = !!thread;
        if (thread) {
            status = summarize_main(p);
        }
    }
    ExitProcess(status);
}
#endif  // _WIN32


#ifdef __linux
// Linux platform
#define _GNU_SOURCE
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

static Size platform_read(int fd, Byte *p, Size len)
{
    Size r = read(fd, p, len);
    return r<0 ? 0 : r;
}

static Bool platform_write(int fd, Byte *p, Size len)
{
    Size off = 0;
    while (off < len) {
        Size r = write(fd, p+off, len-off);
        if (r < 0) {
            return 0;
        }
        off += r;
    }
    return 1;
}

static Bool platform_wait(int *p, int expect, int ms)
{
    struct timespec ts = {ms/1000, ms%1000 * 1000000L};
    return !syscall(SYS_futex, p, FUTEX_WAIT, expect, &ts);
}

static void platform_wake(int *p)
{
    syscall(SYS_futex, p, FUTEX_WAKE, 1);
}

static int linux_thread(void *ctx)
{
    summarize_thread(ctx);
    return 0;
}

int main(void)
{
    int heap_size = 1<<21;
    int heap_prot = PROT_READ | PROT_WRITE;
    int heap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *heap = mmap(0, heap_size, heap_prot, heap_flags, -1, 0);
    if (heap == MAP_FAILED) {
        return 1;
    }

    void *ctx = summarize_init(heap, heap_size/2);
    if (!ctx) {
        return 1;
    }

    int clone_flags = 0;
    clone_flags |= CLONE_FILES;
    clone_flags |= CLONE_FS;
    clone_flags |= CLONE_SIGHAND;
    clone_flags |= CLONE_SYSVSEM;
    clone_flags |= CLONE_THREAD;
    clone_flags |= CLONE_VM;
    void *stack = (Byte *)heap + heap_size;
    if (clone(linux_thread, stack, clone_flags, ctx, 0, 0, 0) == -1) {
        return 1;
    }

    return summarize_main(ctx);
}
#endif  // __linux
