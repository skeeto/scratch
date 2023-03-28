// libc-free x86-64 Linux multi-threading example
//   $ cc -nostdlib stack_head.c
// Ref: https://nullprogram.com/blog/2023/03/23/
// This is free and unencumbered software released into the public domain.

#define SYS_write      1
#define SYS_mmap       9
#define SYS_nanosleep  35
#define SYS_clone      56
#define SYS_exit       60
#define SYS_futex      202
#define SYS_exit_group 231

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

#define SYSCALL1(n, a) \
    syscall6(n,(long)(a),0,0,0,0,0)
#define SYSCALL2(n, a, b) \
    syscall6(n,(long)(a),(long)(b),0,0,0,0)
#define SYSCALL3(n, a, b, c) \
    syscall6(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define SYSCALL4(n, a, b, c, d) \
    syscall6(n,(long)(a),(long)(b),(long)(c),(long)(d),0,0)
#define SYSCALL5(n, a, b, c, d, e) \
    syscall6(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),0)
#define SYSCALL6(n, a, b, c, d, e, f) \
    syscall6(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))

static long syscall6(long n, long a, long b, long c, long d, long e, long f)
{
    register long ret;
    register long r10 asm("r10") = d;
    register long r8  asm("r8")  = e;
    register long r9  asm("r9")  = f;
    __asm volatile (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static void millisleep(int ms)
{
    long ts[] = {ms/1000, ms%1000 * 1000000L};
    SYSCALL2(SYS_nanosleep, ts, ts);
}

static long fullwrite(int fd, void *buf, long len)
{
    for (long off = 0; off < len;) {
        long r = SYSCALL3(SYS_write, fd, buf+off, len-off);
        if (r < 0) {
            return r;
        }
        off += r;
    }
    return len;
}

__attribute((noreturn))
static void exit(int status)
{
    SYSCALL1(SYS_exit, status);
    __builtin_unreachable();
}

__attribute((noreturn))
static void exit_group(int status)
{
    SYSCALL1(SYS_exit_group, status);
    __builtin_unreachable();
}

static void futex_wait(int *futex, int expect)
{
    SYSCALL4(SYS_futex, futex, FUTEX_WAIT, expect, 0);
}

static void futex_wake(int *futex)
{
    SYSCALL3(SYS_futex, futex, FUTEX_WAKE, 0x7fffffff);
}

struct __attribute((aligned(16))) stack_head {
    void (*entry)(struct stack_head *);
    char *message;
    long message_length;
    int print_count;
    int join_futex;
};

__attribute((naked))
static long newthread(struct stack_head *stack)
{
    __asm volatile (
        "mov  %%rdi, %%rsi\n"     // arg2 = stack
        "mov  $0x50f00, %%edi\n"  // arg1 = clone flags
        "mov  $56, %%eax\n"       // SYS_clone
        "syscall\n"
        "mov  %%rsp, %%rdi\n"     // entry point argument
        "ret\n"
        : : : "rax", "rcx", "rsi", "rdi", "r11", "memory"
    );
}

static void threadentry(struct stack_head *stack)
{
    char *message = stack->message;
    int length = stack->message_length;
    int count = stack->print_count;
    for (int i = 0; i < count; i++) {
        fullwrite(1, message, length);
        millisleep(25);
    }
    __atomic_store_n(&stack->join_futex, 1, __ATOMIC_SEQ_CST);
    futex_wake(&stack->join_futex);
    exit(0);
}

static struct stack_head *newstack(long size)
{
    unsigned long p = SYSCALL6(SYS_mmap, 0, size, 3, 0x22, -1, 0);
    if (p > -4096UL) {
        return 0;
    }
    long count = size / sizeof(struct stack_head);
    return (struct stack_head *)p + count - 1;
}

__attribute((force_align_arg_pointer))
void _start(void)
{
    struct stack_head *stack = newstack(1<<16);
    stack->entry = threadentry;
    stack->message = "hello world\n";
    stack->message_length = 12;
    stack->print_count = 20;
    stack->join_futex = 0;
    newthread(stack);
    futex_wait(&stack->join_futex, 0);
    exit_group(0);
}
