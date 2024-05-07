// libc-free vfork+execve on Linux
// $ musl-gcc -static -nostartfiles -ffreestanding -o vfork vfork.c
// $ ./vfork echo hello world
//
// It is impossible to safely call vfork from a high level language,
// including C, even through a libc wrapper. Nearly all vforks in the
// wild are unsafe and rely on luck, i.e. that the wrong registers are
// not spilled between vfork and execve in common build configurations.
// POSIX vfork is impossible to use correctly in any case, but Linux
// vfork is defined thoroughly enough to use in low level languages.
//
// The afork function in this program is implemented in assembly, and
// the new child process runs on a fresh, temporary stack. It reports
// the exact execve result back to the parent via shared memory, and
// does not rely on a special exit status, a la glibc. The user setup
// function configures the new process (dup2, etc.), and can be safely
// implemented in a high level language like C. With libc fully out of
// the picture, the only vfork hazards (global state, deadlocks, etc.)
// you need to worry about are the ones you created for yourself.
//
// Unrelated to vfork, this program demonstrates handy tricks for
// working without libc on Linux: allocation, string processing, path
// handling, buffered output, environment variables, and hash maps.
//
// Ref: https://nullprogram.com/blog/2023/03/23/
// Ref: https://gist.github.com/nicowilliams/a8a07b0fc75df05f684c23c18d7db234
// This is free and unencumbered software released into the public domain.

#define countof(a)         (iz)(sizeof(a) / sizeof(*(a)))
#define assert(c)          while (!(c)) __builtin_unreachable()
#define new(a, t, n)       (t *)allocend(a, sizeof(t), _Alignof(t), n)
#define newbeg(a, t, n)    (t *)allocbeg(a, sizeof(t), _Alignof(t), n)
#define s8(s)              (s8){(u8 *)s, countof(s)-1}
#define newstack(a, t, n)  (new(a, t, (n)/sizeof(t)) + (n)/sizeof(t) - 1)

typedef unsigned char u8;
typedef   signed int  b32;
typedef   signed int  i32;
typedef unsigned int  u32;
typedef   signed long iz;
typedef unsigned long uz;
typedef          char byte;

enum {
    SYS_read    =  0,
    SYS_write   =  1,
    SYS_close   =  3,
    SYS_brk     = 12,
    SYS_access  = 21,
    SYS_pipe    = 22,
    SYS_dup2    = 33,
    SYS_clone   = 56,
    SYS_execve  = 59,
    SYS_exit    = 60,
    SYS_wait4   = 61,
};

enum {
    SIGCHLD     = 17,
    CLONE_VM    = 0x00000100,
    CLONE_VFORK = 0x00004000,
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

static iz read(i32 fd, u8 *buf, iz len)
{
    return syscall3(SYS_read, fd, (uz)buf, len);
}

static iz write(i32 fd, u8 *buf, iz len)
{
    return syscall3(SYS_write, fd, (uz)buf, len);
}

static i32 close(i32 fd)
{
    return (i32)syscall1(SYS_close, fd);
}

static i32 access(u8 *path, i32 mode)
{
    return (i32)syscall2(SYS_access, (uz)path, mode);
}

static i32 pipe(i32 *fds)
{
    return (i32)syscall1(SYS_pipe, (uz)fds);
}

static i32 dup2(i32 old, i32 new)
{
    return (i32)syscall2(SYS_dup2, old, new);
}

static i32 execve(u8 *path, u8 **argv, u8 **envp)
{
    return (i32)syscall3(SYS_execve, (uz)path, (uz)argv, (uz)envp);
}

__attribute((noreturn))
static void exit(i32 r)
{
    asm ("syscall" :: "a"(SYS_exit), "D"(r));
    __builtin_unreachable();
}

static i32 wait4(i32 pid, i32 *status, i32 options, void *rusage)
{
    return (i32)syscall4(SYS_wait4, pid, (uz)status, options, (uz)rusage);
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

// Create a new process with vfork, and run the setup function in the
// child on the stack. The stack should be created with newstack. The
// stack head must be a 16-byte-aligned struct whose first element is a
// setup function pointer, whose single parameter receives the stack
// head.
//
//    struct __attribute((aligned(16))) stack_head {
//        void (*setup)(struct stack_head *) __attribute((noreturn));
//        // ...
//    };
//
// The setup function configures the child (dup2(2), etc.), then calls
// execve(2), storing its result in the stack head object. The setup
// function MUST NOT return, but exit(2) or otherwise terminate itself
// should execve fail.
//
// afork() returns to the parent after the child is done with the stack,
// forming a happens-before synchronization edge. The execve result may
// be safely retrieved, and the stack may be discarded/reused.
__attribute((naked))
static i32 afork(void *stackhead)
{
    asm volatile (
        "mov    %%rdi, %%rsi\n"
        "mov    %0, %%edi\n"
        "mov    %1, %%eax\n"
        "syscall\n"
        "mov    %%rsp, %%rdi\n"
        "ret\n"
        :
        : "i"(SIGCHLD|CLONE_VM|CLONE_VFORK), "i"(SYS_clone)
        : "rcx", "r11", "memory"
    );
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
            i32 r = (i32)write(b->fd, b->buf+off, b->len-off);
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

typedef struct forkstack forkstack;
struct __attribute((aligned(16))) forkstack {
    void (*setup)(forkstack *) __attribute((noreturn));
    u8    *path;
    u8   **argv;
    u8   **envp;
    i32    execve;
};

__attribute((noreturn))
static void setupproc(forkstack *f)
{
    // ... additional configuration (dup2, etc.) ...
    f->execve = execve(f->path, f->argv, f->envp);
    exit(127);
}

typedef struct capout capout;
struct __attribute((aligned(16))) capout {
    void (*setup)(capout *) __attribute((noreturn));
    u8    *path;
    u8   **argv;
    u8   **envp;
    i32    execve;
    i32    fds[2];
};

__attribute((noreturn))
static void setupcapout(capout *f)
{
    close(f->fds[0]);
    dup2(f->fds[1], 1);
    close(f->fds[1]);
    f->execve = execve(f->path, f->argv, f->envp);
    exit(127);
}

// Start the given program and capture its output as a string.
static s8 capture(u8 *path, u8 **argv, u8 **envp, arena *perm)
{
    s8  r   = {0};
    i32 pid = 0;
    i32 fd  = 0;

    {
        arena scratch = *perm;
        capout *stack = newstack(&scratch, capout, 1<<12);
        stack->setup  = setupcapout;
        stack->path   = path;
        stack->argv   = argv;
        stack->envp   = envp;
        pipe(stack->fds);

        pid = afork(stack);
        close(stack->fds[1]);
        fd = stack->fds[0];

        if (pid < 0) {
            close(fd);
            return r;
        } else if (stack->execve) {
            close(fd);
            wait4(pid, 0, 0, 0);
            return r;
        }
    }

    // Stack no longer in use, now use it to capture output.
    r.data = (u8 *)perm->beg;
    iz cap = perm->end - perm->beg;
    while (r.len < cap) {
        iz len = read(fd, r.data+r.len, cap-r.len);
        if (len < 1) break;
        r.len += len;
    }
    close(fd);

    if (pid != wait4(pid, 0, 0, 0)) {
        r.data = 0;
        r.len  = 0;
    } else {
        perm += r.len;
    }
    return r;
}

static i32 run(i32 argc, u8 **argv, u8 **envp)
{
    if (argc < 2) return 1;

    arena scratch = newarena(1<<21);
    u8buf *stderr = newu8buf(2, 1<<12, &scratch);
    env *environ  = newenv(envp, &scratch);

    s8 path  = getenv(environ, s8("PATH"));
    s8 exe   = findexe(path, s8import(argv[1]), &scratch);
    exe.len -= !!exe.len;
    print(stderr, s8("path   = "));
    print(stderr, exe);
    print(stderr, s8("\n"));

    forkstack *stack = newstack(&scratch, forkstack, 1<<12);
    stack->setup = setupproc;
    stack->path  = exe.data;
    stack->argv  = argv + 1;
    stack->envp  = envp;

    i32 pid    = afork(stack);
    i32 status = 0;
    i32 wait4r = 0;
    if (pid > 0) {
        wait4r = wait4(pid, &status, 0, 0);
    }

    print   (stderr, s8("pid    = "));
    printi32(stderr, pid);
    print   (stderr, s8("\n"));
    print   (stderr, s8("execve = "));
    printi32(stderr, stack->execve);
    print   (stderr, s8("\n"));
    print   (stderr, s8("status = "));
    printi32(stderr, status);
    print   (stderr, s8("\n"));
    print   (stderr, s8("wait4  = "));
    printi32(stderr, wait4r);
    print   (stderr, s8("\n"));
    flush   (stderr);

    u8 *calexe = findexe(path, s8("cal"), &scratch).data;
    u8 *calargv[] = {s8("cal").data, s8("5").data, s8("2024").data, 0};
    s8 cal = capture(calexe, calargv, envp, &scratch);
    print   (stderr, s8("\"cal 5 2024\" output ("));
    printi32(stderr, (i32)cal.len);
    print   (stderr, s8(" bytes):\n"));
    print   (stderr, cal);
    flush   (stderr);

    return status;
}

void entrypoint(uz *stack)
{
    i32  argc = (i32)*stack;
    u8 **argv = (u8 **)(stack+1);
    u8 **envp = argv + argc + 1;
    i32 r = run(argc, argv, envp);
    exit(r);
}

asm (
    "_start: .globl _start\n"
    "        mov %rsp, %rdi\n"
    "        call entrypoint\n"
);
