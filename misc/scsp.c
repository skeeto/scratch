// Lock-free single-consumer, single-producer generic queue
//
// Nothing novel, but it has some nice properties:
// * Uses only acquire/release loads and stores
// * On x86: no lock prefix, only relies on inherent TSO
// * Generic, supports queues of any type, without macros
// * No allocations, caller owns the circular buffer
// * No libc dependency, works in libc-free programs
// * Supports all three major C compilers
//
// While the queue has some new (to me in March 2023) insights, it's
// mostly a red herring. This project captures knowledge and technique
// acquired in figuring out libc-free threads for the test framework.
//
// For Linux, I had figured it out back in 2015, but never used it in a
// practical application. I wanted to make the raw clone syscall here
// with as little assembly as possible, including join functionality. I
// managed to spawn the new thread with a simple interface in just 8
// assembly instructions.
//
// The clone syscall is a mess and always requires per-target assembly
// beyond the syscall itself, because the semantics cannot be expressed
// in C. The syscall return behaves like fork(2), but for the new thread
// it's actually a function call, e.g. no stack frame is present. That's
// a problem: The intruction pointer is in the middle of a function. So
// the assembly must return to C through a function call. Despite having
// all the information to do better, the kernel half-asses the job, even
// in the new clone3. If it did just a tiny bit more setup, per-target
// assembly would be unnecessary.
//
// This is free and unencumbered software released into the public domain.


// SCSP Queue

#ifdef _MSC_VER
  // MSVC volatile has acquire/release semantics
  #define __atomic_load_n(p, c) (*(volatile int *)p)
  #define __atomic_store_n(p, a, c) (*(volatile int *)p = a)
#endif

// A single-producer, single-consumer queue.
typedef struct {
    int head;
    int tail;
    int mask;
} Queue;

// Initialize a queue for a positive, power-of-two number of slots.
static Queue queue_init(int nslots)
{
    Queue q = {0};
    q.mask = nslots - 1;
    return q;
}

// Begin pushing an item into the queue. Returns the slot index, or -1
// if no space is available.
static int queue_push(Queue *q)
{
    int head = q->head;
    int next = (head + 1u) & q->mask;
    int tail = __atomic_load_n(&q->tail, __ATOMIC_ACQUIRE);
    return next==tail ? -1 : head;
}

// Finish pushing an item into the queue.
static void queue_push_commit(Queue *q)
{
    int head = q->head;
    int next = (head + 1u) & q->mask;
    __atomic_store_n(&q->head, next, __ATOMIC_RELEASE);
}

// Begin popping the next item from the queue. Returns its slot index,
// or -1 if the queue is empty.
static int queue_pop(Queue *q)
{
    int tail = q->tail;
    int head = __atomic_load_n(&q->head, __ATOMIC_ACQUIRE);
    return head==tail ? -1 : tail;
}

// Finish popping the next item from the queue.
static void queue_pop_commit(Queue *q)
{
    int tail = q->tail;
    int next = (tail + 1u) & q->mask;
    __atomic_store_n(&q->tail, next, __ATOMIC_RELEASE);
}


// Platform API

static void platform_write(void *, int);


// Test Application
//
// The main thread passes a million integers, starting from zero, to the
// other thread using the queue, which prints them out. The MD5 hash of
// the output should be 762251ff53a76f10ada68131f8e3d4c1.
//
// The platform calls appinit() for configuration, then calls appentry()
// from two threads, id=0 and id=1. The process does not terminate until
// both threads have returned. The exit status is the return from thread
// id=0.

#define countof(a) (int)(sizeof(a) / sizeof(*(a)))

typedef struct {
    Queue queue;
    int slots[1<<6];
} IntQueue;

static void appinit(void *heap)
{
    IntQueue *q = heap;
    q->queue = queue_init(countof(q->slots));
}

static void worker(IntQueue *q)
{
    for (;;) {
        int slot;
        do {
            slot = queue_pop(&q->queue);
        } while (slot < 0);
        int v = q->slots[slot];
        queue_pop_commit(&q->queue);
        if (v < 0) {
            break;
        }

        char buf[32], *e = buf+32, *p = e;
        *--p = '\n';
        do {
            *--p = '0' + (char)(v%10);
        } while (v /= 10);
        platform_write(p, (int)(e-p));
    }
}

static int appentry(void *heap, int threadid)
{
    IntQueue *q = heap;

    if (threadid != 0) {
        worker(q);
        return 0;
    }

    for (int i = 0; i < 1000000; i++) {
        int slot;
        do {
            slot = queue_push(&q->queue);
        } while (slot < 0);
        q->slots[slot] = i;
        queue_push_commit(&q->queue);
    }

    int slot;
    do {
        slot = queue_push(&q->queue);
    } while (slot < 0);
    q->slots[slot] = -1;
    queue_push_commit(&q->queue);
    return 0;
}


// CRT-free Windows Platform
//   $ cc -nostartfiles -o scsp scsp.c
//   $ cl scsp.c
#if _WIN32
#if __GNUC__
  typedef __SIZE_TYPE__ size_t;
#endif
#ifdef _MSC_VER
  #pragma comment(lib, "kernel32.lib")
  #pragma comment(linker, "/subsystem:console")
#endif

typedef int (__stdcall *THRPROC)(void *);
__declspec(dllimport)
void *__stdcall CreateThread(void *, size_t, THRPROC, void *, int, int *);
__declspec(dllimport)
void *__stdcall GetStdHandle(int);
__declspec(dllimport)
void *__stdcall VirtualAlloc(void *, size_t, int, int);
__declspec(dllimport)
int __stdcall WaitForSingleObject(void *, int);
__declspec(dllimport)
int __stdcall WriteFile(void *, void *, int, int *, void *);

#if __i686__
__attribute((force_align_arg_pointer))
#endif
static int __stdcall threadentry(void *arg)
{
    return appentry(arg, 1);
}

static void platform_write(void *buf, int len)
{
    void *h = GetStdHandle(-11);
    WriteFile(h, buf, len, &len, 0);
}

#if __i686__
__attribute((force_align_arg_pointer))
#endif
int mainCRTStartup(void)
{
    void *heap = VirtualAlloc(0, 1<<16, 0x3000, 4);
    appinit(heap);
    void *thread = CreateThread(0, 0, threadentry, heap, 0, 0);
    int r = appentry(heap, 0);
    WaitForSingleObject(thread, -1);
    return r;
}


// libc-free amd64 Linux
#elif __linux && __amd64 && !__STDC_HOSTED__
//   $ cc -ffreestanding -nostdlib -o scsp scsp.c

#define SYS_write      1
#define SYS_mmap       9
#define SYS_clone      56
#define SYS_exit       60
#define SYS_futex      202
#define SYS_exit_group 231
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

static long syscall1(long n, long a)
{
    long r;
    __asm volatile (
        "syscall"
        : "=a"(r)
        : "a"(n), "D"(a)
        : "rcx", "r11", "memory", "cc"
    );
    return r;
}

static long syscall3(long n, long a, long b, long c)
{
    long r;
    __asm volatile (
        "syscall"
        : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c)
        : "rcx", "r11", "memory", "cc"
    );
    return r;
}

static long syscall4(long n, long a, long b, long c, long d)
{
    long r;
    register long r10 asm("r10") = d;
    __asm volatile (
        "syscall"
        : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
        : "rcx", "r11", "memory", "cc"
    );
    return r;
}

static long syscall6(long n, long a, long b, long c, long d, long e, long f)
{
    long r;
    register long r10 asm("r10") = d;
    register long r8  asm("r8")  = e;
    register long r9  asm("r9")  = f;
    __asm volatile (
        "syscall"
        : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory", "cc"
    );
    return r;
}

__attribute((noreturn))
static void exit(int r)
{
    syscall1(SYS_exit, r);
    __builtin_unreachable();
}

__attribute((noreturn))
static void exit_group(int r)
{
    syscall1(SYS_exit_group, r);
    __builtin_unreachable();
}

typedef struct __attribute((aligned(16))) {
    void (*entry)(void *);
    int join_futex;
} StackHead;

// Spawn a thread using the configured stack. The caller defines a
// struct whose first element is a StackHead, a pointer to which is
// passed to this function. This struct must be allocated at the high
// end of the stack with proper alignment. (Hint: Treat the stack as an
// array of these structs and pick the last.) The entry field must be
// populated with the thread entry point, which receives the StackHead
// pointer upon entry. That is, a pointer to the custom struct. The new
// thread must not return from its entry point.
//
// The join_futex field will be initialized. It is atomically zeroed
// after the thread exits, then poked as a single-wakeup futex. To join,
// futex-wait until the futex is zero. Returns a negative errno or a
// positive thread id.
__attribute((naked))
static int newthread(__attribute((unused)) StackHead *stack)
{
    __asm volatile (
        "lea   8(%%rdi), %%r10\n"   // arg4 = &stack->join_futex
        "movl  $1, (%%r10)\n"       // stack->join_futex = 1
        "mov   %%rdi, %%rsi\n"      // arg2 = stack
        "mov   $0x250f00, %%edi\n"  // arg1 = clone flags
        "mov   $56, %%eax\n"        // SYS_clone
        "syscall\n"
        "mov   %%rsp, %%rdi\n"      // thread entry point argument
        "ret\n"
        : : : "rax", "rcx", "rsi", "rdi", "r10", "r11", "memory", "cc"
    );
}

static void jointhread(StackHead *stack)
{
    syscall4(SYS_futex, (long)&stack->join_futex, FUTEX_WAIT, 1, 0);
}

static void platform_write(void *buf, int len)
{
    char *p = buf;
    for (int off = 0; off < len;) {
        int r = syscall3(SYS_write, 1, (long)(p+off), len-off);
        switch (r) {
        case -1: return;
        default: off += r;
        }
    }
}

typedef struct {
    StackHead head;
    void *heap;
} ThreadData;

static void threadentry(void *arg)
{
    ThreadData *data = arg;
    appentry(data->heap, 1);
    exit(0);
}

__attribute((force_align_arg_pointer))
void _start(void)
{
    // Allocate a heap and stack
    int heapsize = 1<<16;
    unsigned long p = syscall6(SYS_mmap, 0, heapsize, 3, 0x22, -1, 0);
    if (p > -4096UL) {
        exit_group(1);
    }
    ThreadData *data = (ThreadData *)p + heapsize/sizeof(ThreadData) - 1;
    data->head.entry = threadentry;
    data->heap = (void *)p;

    appinit(data->heap);

    int tid = newthread(&data->head);
    if (tid < 0) {
        exit_group(1);
    }
    int r = appentry(data->heap, 0);
    jointhread(&data->head);
    exit_group(r);
}


// Generic Unix Platform
#elif __unix || __APPLE__ || __HAIKU__
//   $ cc -pthread -o scsp scsp.c
// Compatible with Thread Sanitizer: -fsanitize=thread
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

static void platform_write(void *buf, int len)
{
    char *p = buf;
    for (int off = 0; off < len;) {
        int r = write(1, p+off, len-off);
        switch (r) {
        case -1: return;
        default: off += r;
        }
    }
}

static void *threadentry(void *heap)
{
    return (void *)(long)appentry(heap, 1);
}

int main(void)
{
    void *heap = malloc(1<<16);
    appinit(heap);
    pthread_t thread;
    pthread_create(&thread, 0, threadentry, heap);
    int r = appentry(heap, 0);
    pthread_join(thread, 0);
    return r;
}
#endif
