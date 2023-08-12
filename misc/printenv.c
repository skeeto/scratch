// Print arguments and environment variables on Linux without libc
//
// Twofold purpose: (1) Demonstrate a technique for minimal assembly
// entry points, typically only two instructions. Access to argv, envp,
// and auxv requires only the stack pointer on entry. The entry point
// aligns the stack, then passes the pre-aligned address into C. All
// else can be done in portable C. (2) It took some effort to work out
// and debug the details. This captures it for future reference.
//
// Four architectures supported: amd64, i386, arm64, arm. That covers
// more than 99.9% of all Linux systems today (2023). Other interesting
// targets would be ppc, ppc64, and riscv. The amd64 and i386 targets
// also work with tcc (mob).
//
// Simplest build, using only required flags:
// $ cc -static -fno-builtin -nostdlib printenv.c
//
// Minimal, distribution-invariant executable:
// $ cc -static -fno-pie -fno-builtin -fno-asynchronous-unwind-tables -Oz -s
//      -nostdlib -Wl,--gc-sections -Wl,--build-id=none -Wl,--nmagic printenv.c
//
// Position Independent Executable (PIE), requires specific dynamic linker:
// $ cc -fpie -fno-builtin -fno-asynchronous-unwind-tables -Oz -s
//      -nostdlib -pie -Wl,--gc-sections -Wl,--build-id=none printenv.c
//
// This is free and unencumbered software released into the public domain.

typedef long size;
typedef _Bool bool;
typedef unsigned char byte;

// Clang and GCC may generate memset calls despite -fno-builtin-memset.
// Volatile avoids GCC miscompile into an infinite loop. Both cases are
// compiler bugs. Also required for tcc builds.
void *memset(void *buf, int c, unsigned long len)
{
    volatile byte *dst = buf;
    for (; len; len--) {
        *dst++ = (byte)c;
    }
    return buf;
}


#if __amd64__
asm (
    "        .globl _start\n"
    "_start: mov   %rsp, %rdi\n"
    "        call  entrypoint\n"
);

static void exit(byte status)
{
    asm ("syscall" : : "a"(60), "D"((int)status));
    __builtin_unreachable();
}

static size write(int fd, void *buf, size len)
{
    long r = 1;
    asm volatile (
        "syscall"
        : "+a"(r)
        : "D"(fd), "S"(buf), "d"(len)
        : "rcx", "r11", "memory"
    );
    return r;
}
#endif


#if __i386__
asm (
    "        .globl _start\n"
    "_start: mov   %esp, %eax\n"
    "        sub   $12, %esp\n"
    "        push  %eax\n"
    "        call  entrypoint\n"
);

static void exit(byte status)
{
    asm ("int $0x80" : : "a"(1), "b"((int)status));
    __builtin_unreachable();
}

static size write(int fd, void *buf, size len)
{
    long r = 4;
    asm volatile (
        "int $0x80"
        : "+a"(r)
        : "b"(fd), "c"(buf), "d"(len)
        : "memory"
    );
    return r;
}
#endif


#if __aarch64__
asm (
    "        .globl _start\n"
    "_start: mov  x0, sp\n"
    "        b    entrypoint\n"
);

static void exit(byte status)
{
    register int x0 __asm("w0") = status;
    register int x8 __asm("w8") = 93;
    asm ("svc #0" : : "r"(x8), "r"(x0));
    __builtin_unreachable();
}

static size write(int fd, void *buf, size len)
{
    register int   x0 __asm("w0") = fd;
    register void *x1 __asm("x1") = buf;
    register long  x2 __asm("x2") = len;
    register int   x8 __asm("w8") = 64;
    asm volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory"
    );
    return x0;
}
#endif


#if __arm__
// NOTE: Use -lgcc for __aeabi_idivmod, required at some optimization levels.
asm (
    "        .globl _start\n"
    "_start: mov  r0, sp\n"
    "        b    entrypoint\n"
);

// libgcc __aeabi_ldiv0 stupidly calls raise
void raise(void) { __builtin_trap(); }

static void exit(byte status)
{
    register int r0 __asm("r0") = status;
    register int r8 __asm("r7") = 1;
    asm ("svc #0" : : "r"(r8), "r"(r0));
    __builtin_unreachable();
}

static size write(int fd, void *buf, size len)
{
    register int   r0 __asm("r0") = fd;
    register void *r1 __asm("r1") = buf;
    register long  r2 __asm("r2") = len;
    register int   r8 __asm("r7") = 4;
    asm volatile (
        "svc #0"
        : "+r"(r0)
        : "r"(r8), "r"(r1), "r"(r2)
        : "memory"
    );
    return r0;
}
#endif


// Platform-agnostic application

typedef struct {
    byte *buf;
    size  cap;
    size  len;
    int   fd;
    bool  err;
} bufout;

static void flush(bufout *o)
{
    for (size off = 0; !o->err && off<o->len;) {
        size r = write(o->fd, o->buf+off, o->len-off);
        o->err = r < 1;
        off   += r;
    }
    o->len = 0;
}

static void print(bufout *o, byte *buf, size len)
{
    byte *end = buf + len;
    while (!o->err && buf<end) {
        size avail = o->cap - o->len;
        size count = end-buf<avail ? end-buf : avail;
        byte *dst  = o->buf + o->len;
        for (size i = 0; i < count; i++) {
            dst[i] = buf[i];
        }
        buf += count;
        o->len += count;
        if (o->len == o->cap) {
            flush(o);
        }
    }
}

#define PRINTS(out, s) print(out, (byte *)s, sizeof(s)-1)
static void prints(bufout *o, byte *str)
{
    size len = 0;
    for (; str[len]; len++) {}
    print(o, str, len);
}

static void printsize(bufout *o, size n)
{
    byte buf[32];
    byte *end = buf + sizeof(buf);
    byte *beg = end;
    size rem  = n>0 ? -n : n;
    do {
        *--beg = (byte)('0' - rem%10);
    } while (rem /= 10);
    beg[-1] = '-';
    beg -= n < 0;
    print(o, beg, end-beg);
}

static byte cmain(size argc, byte **argv, byte **envp)
{
    byte buf[1<<10];
    bufout stdout[1] = {0};
    stdout->buf = buf;
    stdout->cap = sizeof(buf);
    stdout->fd  = 1;

    for (size i = 0; i < argc; i++) {
        PRINTS(stdout, "argv[");
        printsize(stdout, i);
        PRINTS(stdout, "]=");
        prints(stdout, argv[i]);
        PRINTS(stdout, "\n");
    }

    for (byte **env = envp; *env; env++) {
        prints(stdout, env[0]);
        PRINTS(stdout, "\n");
    }

    flush(stdout);
    return stdout->err;
}

__attribute((externally_visible))  // for -fwhole-program
void entrypoint(byte **stack)
{
    size   argc = ((size *)stack)[0];
    byte **argv = (byte **)stack + 1;
    byte **envp = argv + argc + 1;
    exit(cmain(argc, argv, envp));
}
