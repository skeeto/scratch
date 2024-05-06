// libc-free vfork+execve on Linux
// $ musl-gcc -static -nostartfiles -ffreestanding -o vfork vfork.c
// $ ./vfork echo hello world
//
// It is impossible to safely call vfork from a high level language,
// including C, even through a libc wrapper. Nearly all vforks in the
// wild are unsafe and rely on luck, i.e. that the wrong registers are
// not spilled betweeen vfork and execve in common build configurations.
// POSIX vfork is impossible to use correctly in any case, but Linux
// vfork is defined thoroughly enough to use in low level languages.
//
// The startprocess() function is implemented in assembly and should be
// a safe use of vfork. It even reports the precise execve result back
// to the parent (via shared memory), and does not rely on a special
// exit status, a la glibc.
//
// A more configurable enhancement would be an "afork"-like function
// which runs the vfork child on its own stack, allocated out of an
// arena, allowing the safe execution of high level code (dup2(2), etc.)
// on the new stack. With libc fully out of the picture, the only vfork
// hazards (global state, deadlocks, etc.) you need to worry about are
// the ones you created for yourself.
//
// Unrelated to vfork, this program demonstrates handy tricks for
// working without libc on Linux: allocation, string processing, path
// handling, buffered output, environment variables, and hash maps.
//
// This is free and unencumbered software released into the public domain.

#define countof(a)       (iz)(sizeof(a) / sizeof(*(a)))
#define assert(c)        while (!(c)) __builtin_unreachable()
#define new(a, t, n)     (t *)allocend(a, sizeof(t), _Alignof(t), n)
#define newbeg(a, t, n)  (t *)allocbeg(a, sizeof(t), _Alignof(t), n)
#define s8(s)            (s8){(u8 *)s, countof(s)-1}

typedef unsigned char u8;
typedef   signed int  b32;
typedef   signed int  i32;
typedef unsigned int  u32;
typedef   signed long iz;
typedef unsigned long uz;
typedef          char byte;

enum {
    SYS_write   =  1,
    SYS_brk     = 12,
    SYS_access  = 21,
    SYS_vfork   = 58,
    SYS_execve  = 59,
    SYS_exit    = 60,
    SYS_wait4   = 61,
};

static iz syscall1(i32 n, uz a)
{
    iz r;
    asm volatile (
        "syscall"
        : "=a"(r)
        : "a"(n), "D"(a)
        : "rcx", "r11", "memory"
    );
    return r;
}

static iz syscall2(i32 n, uz a, uz b)
{
    iz r;
    asm volatile (
        "syscall"
        : "=a"(r)
        : "a"(n), "D"(a), "S"(b)
        : "rcx", "r11", "memory"
    );
    return r;
}

static iz syscall3(i32 n, uz a, uz b, uz c)
{
    iz r;
    asm volatile (
        "syscall"
        : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c)
        : "rcx", "r11", "memory"
    );
    return r;
}


static iz syscall4(i32 n, uz a, uz b, uz c, uz d)
{
    iz r;
    register iz r10 asm("r10") = d;
    asm volatile (
        "syscall"
        : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return r;
}

typedef struct {
    i32 vfork;
    i32 execve;
} procstat;

// vfork(2) then execve(2), returning both results. On success, the
// vfork field will be the PID, and execve field will be zero.
__attribute((naked))
static procstat startprocess(u8 *path, u8 **argv, u8 **envp)
{
    asm volatile (
        "    pushq  $0\n"               // result = {0, 0}
        "    mov    %0, %%eax\n"        // vfork()
        "    syscall\n"                 // "
        "    test   %%eax, %%eax\n"
        "    je     1f\n"               // if parent
        "    mov    %%eax, (%%rsp)\n"   // result.vfork = eax
        "    pop    %%rax\n"            // retrieve result
        "    ret\n"
        "1:  mov    %1, %%eax\n"        // if child
        "    syscall\n"                 // execve()
        "    mov    %%eax, 4(%%rsp)\n"  // result.execve = eax
        "    mov    %2, %%eax\n"        // exit(127)
        "    mov    $127, %%edi\n"      // "
        "    syscall\n"                 // "
        :
        : "i"(SYS_vfork), "i"(SYS_execve), "i"(SYS_exit)
        : "rax", "rcx", "r11", "memory"
    );
}

typedef struct {
    byte *beg;
    byte *end;
} arena;

static arena newarena(iz cap)
{
    arena r = {};
    r.beg = (byte *)syscall1(SYS_brk, 0);
    r.end = (byte *)syscall1(SYS_brk, (uz)(r.beg+cap));
    return r;
}

static byte *allocbeg(arena *a, iz size, iz align, iz count)
{
    iz pad = -(uz)a->beg & (align - 1);
    assert(count < (a->end - a->beg - pad)/size);
    byte *r = a->beg + pad;
    a->beg += pad + count*size;
    return __builtin_memset(r, 0, count*size);
}

static byte *allocend(arena *a, iz size, iz align, iz count)
{
    iz pad = (uz)a->end & (align - 1);
    assert(count < (a->end - a->beg - pad)/size);
    return __builtin_memset(a->end -= pad + count*size, 0, count*size);
}

typedef struct {
    u8 *data;
    iz  len;
} s8;

static s8 s8span(u8 *beg, u8 *end)
{
    s8 r   = {0};
    r.data = beg;
    r.len  = beg ? end-beg : 0;
    return r;
}

static b32 s8equals(s8 a, s8 b)
{
    return a.len==b.len && (!a.len || !__builtin_memcmp(a.data, b.data, a.len));
}

static u32 s8hash(s8 s)
{
    u32 h = 0x100;
    for (iz i = 0; i < s.len; i++) {
        h ^= s.data[i];
        h *= 0xc29d8ca1;
    }
    return h;
}

static s8 s8import(u8 *s)
{
    s8 r = {0};
    r.data = s;
    for (; r.data[r.len]; r.len++) {}
    return r;
}

// Try to concatenate in place, otherwise allocate a fresh string.
static s8 s8concat(s8 head, s8 tail, arena *perm)
{
    if (!head.data || (byte *)(head.data+head.len) != perm->beg) {
        s8 copy = head;
        copy.data = newbeg(perm, u8, head.len);
        __builtin_memcpy(copy.data, head.data, head.len);
        head = copy;
    }

    u8 *data = newbeg(perm, u8, tail.len);
    __builtin_memcpy(data, tail.data, tail.len);
    head.len += tail.len;
    return head;
}

typedef struct {
    s8 head;
    s8 tail;
} s8pair;

// Cut a string on a delimeter. On the last token, tail will be null.
static s8pair s8cut(s8 s, u8 c)
{
    s8pair r = {0};
    if (s.data) {
        u8 *beg = s.data;
        u8 *end = s.data + s.len;
        u8 *cut = beg;
        for (; cut<end && *cut!=c; cut++) {}
        r.head = s8span(beg, cut);
        if (cut < end) {
            r.tail = s8span(cut+1, end);
        }
    }
    return r;
}

typedef struct {
    u8 *buf;
    i32 len;
    i32 cap;
    i32 fd;
    b32 err;
} u8buf;

static u8buf *newu8buf(i32 fd, i32 cap, arena *perm)
{
    u8buf *r = new(perm, u8buf, 1);
    r->buf = new(perm, u8, cap);
    r->cap = cap;
    r->fd  = fd;
    return r;
}

static void flush(u8buf *b)
{
    if (!b->err) {
        for (i32 off = 0; off < b->len;) {
            i32 r = (i32)syscall3(
                SYS_write, b->fd, (uz)(b->buf+off), b->len-off
            );
            if (r < 1) {
                b->err = 1;
                break;
            }
            off += r;
        }
        b->len = 0;
    }
}

static void print(u8buf *b, s8 s)
{
    for (iz off = 0; !b->err && off<s.len;) {
        i32 avail = b->cap - b->len;;
        i32 count = avail<s.len-off ? avail : (i32)(s.len-off);
        __builtin_memcpy(b->buf+b->len, s.data+off, count);
        off += count;
        b->len += count;
        if (b->len == b->cap) {
            flush(b);
        }
    }
}

static void printi32(u8buf *b, i32 x)
{
    u8  buf[32];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    i32 t = x<0 ? x : -x;
    do {
        *--beg = '0' - (u8)(t%10);
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    print(b, s8span(beg, end));
}

static i32 access(u8 *path, i32 mode)
{
    return (i32)syscall2(SYS_access, (uz)path, mode);
}

// Search $PATH for the named program. The returned string includes a null
// terminator, ready for use in execve(2).
static s8 findexe(s8 pathenv, s8 name, arena *perm)
{
    for (iz i = 0; i < name.len; i++) {
        if (name.data[i] == '/') {
            return s8concat(name, s8("\0"), perm);
        }
    }

    s8pair r = {0};
    r.tail = pathenv;
    while (r.tail.data) {
        r = s8cut(r.tail, ':');

        arena temp = *perm;
        s8 base = r.head;
        if (base.len && base.data[base.len-1]!='/') {
            base = s8concat(base, s8("/"), &temp);
        }
        base = s8concat(base, name, &temp);
        base = s8concat(base, s8("\0\0"), &temp);

        // Can we read and execute it?
        enum { R_OK = 1, X_OK = 4 };
        if (access(base.data, R_OK|X_OK)) {
            continue;
        }

        // But is it a directory?
        base.data[base.len-2] = '/';
        if (!access(base.data, R_OK|X_OK)) {
            continue;
        }

        *perm = temp;  // keep it
        base.len--;    // chop '/'
        base.data[base.len-1] = 0;
        return base;
    }

    return s8concat(name, s8("\0"), perm);
}

typedef struct env env;
struct env {
    env *child[2];
    s8   name;
    s8   value;
};

static s8 *upsertenv(env **e, s8 name, arena *perm)
{
    for (u32 h = s8hash(name); *e; h <<= 1) {
        if (s8equals(name, (*e)->name)) {
            return &(*e)->value;
        }
        e = &(*e)->child[h>>31];
    }
    if (!perm) {
        return 0;
    }
    *e = new(perm, env, 1);
    (*e)->name = name;
    return &(*e)->value;
}

static env *newenv(u8 **envp, arena *perm)
{
    env *r = 0;
    for (u8 **e = envp; *e; e++) {
        s8pair pair = s8cut(s8import(*e), '=');
        *upsertenv(&r, pair.head, perm) = pair.tail;
    }
    return r;
}

static s8 getenv(env *e, s8 name)
{
    s8 null = {0};
    s8 *r = upsertenv(&e, name, 0);
    return r ? *r : null;
}

static i32 run(i32 argc, u8 **argv, u8 **envp)
{
    if (argc < 2) return 1;

    arena scratch = newarena(1<<21);
    u8buf *stdout = newu8buf(1, 1<<12, &scratch);
    env *environ  = newenv(envp, &scratch);

    s8 path  = getenv(environ, s8("PATH"));
    s8 exe   = findexe(path, s8import(argv[1]), &scratch);
    exe.len -= !!exe.len;
    print(stdout, s8("path   = "));
    print(stdout, exe);
    print(stdout, s8("\n"));

    procstat r = startprocess(exe.data, argv+1, envp);
    i32 pid    = r.vfork;
    i32 status = 0;
    i32 wait4  = 0;
    if (pid > 0) {
        wait4 = (i32)syscall4(SYS_wait4, pid, (uz)&status, 0, 0);
    }

    print   (stdout, s8("pid    = "));
    printi32(stdout, pid);
    print   (stdout, s8("\n"));
    print   (stdout, s8("execve = "));
    printi32(stdout, r.execve);
    print   (stdout, s8("\n"));
    print   (stdout, s8("status = "));
    printi32(stdout, status);
    print   (stdout, s8("\n"));
    print   (stdout, s8("wait4  = "));
    printi32(stdout, wait4);
    print   (stdout, s8("\n"));
    flush   (stdout);

    return status;
}

void entrypoint(uz *stack)
{
    i32  argc = (i32)*stack;
    u8 **argv = (u8 **)(stack+1);
    u8 **envp = argv + argc + 1;
    i32 r = run(argc, argv, envp);
    asm ("syscall" :: "a"(SYS_exit), "D"(r));
    __builtin_unreachable();
}

asm (
    "_start: .globl _start\n"
    "        mov %rsp, %rdi\n"
    "        call entrypoint\n"
);
