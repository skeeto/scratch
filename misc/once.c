// "once" implementation using load, store, and increment on a futex
//   int once = 0;
//   // ...
//   if (do_once(&once)) {
//        // ... init ...
//        once_done(&once);
//   }
// Ref: https://nullprogram.com/blog/2023/07/31/
// This is free and unencumbered software released into the public domain.
#include <limits.h>

// Synchronization primitives
static int  load(int *);
static void store(int *, int);
static int  incr(int *);
static void wait(int *, int);
static void wake(int *);

static _Bool do_once(int *once)
{
    int r = load(once);
    if (r < 0) {
        return 0;
    } else if (r == 0) {
        r = incr(once);
        if (r == 1) {
            return 1;
        }
    }
    while (r > 0) {
        wait(once, r);
        r = load(once);
    }
    return 0;
}

static void once_done(int *once)
{
    store(once, INT_MIN);
    wake(once);
}

// Thread entry point for all threads. There is no "leader" thread, and
// the shared memory must be zero initialized.
static void test_once(void *shared, int nthreads)
{
    #define ASSERT(c) if (!(c)) *(volatile int *)0 = 0
    struct test {
        int barrier;
        int signal;
        int once;
        int test;
    } *t = shared;

    for (int i = 0; i < 10000; i++) {
        if (incr(&t->barrier) == nthreads) {
            // Last thread to the barrier, so initialize the test
            t->barrier = t->once = t->test = 0;
            store(&t->signal, i+1);
            wake(&t->signal);
        } else {
            do {
                wait(&t->signal, i);
                // A wake may arrive from the previous iteraion, so
                // check for the specific wake event.
            } while (load(&t->signal) != i+1);
        }

        if (do_once(&t->once)) {
            t->test++;
            once_done(&t->once);
        }
        ASSERT(t->test == 1);
    }
}


#if __GNUC__
static int load(int *p) { return __atomic_load_n(p, __ATOMIC_SEQ_CST); }
static void store(int *p, int v) { __atomic_store_n(p, v, __ATOMIC_SEQ_CST); }
static int incr(int *p) { return __atomic_add_fetch(p, 1, __ATOMIC_SEQ_CST); }
#elif _MSC_VER
static int load(int *p) { return *(volatile int *)p; }
static void store(int *p, int v) { *(volatile int *)p = v; }
static int incr(int *p) { return _InterlockedIncrement((long *)p); }
#endif


#if _WIN32
// $ cc -nostartfiles -o once once.c
// $ cl once.c /link /subsystem:console kernel32.lib
// $ ./once || echo failed
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define NTHREADS 64

static int (__stdcall *nt_RtlWaitOnAddress)(void *, void *, size_t, void *);
static int (__stdcall *nt_RtlWakeAddressAll)(void *);

static void wake(int *p)
{
    if (nt_RtlWakeAddressAll) {
        nt_RtlWakeAddressAll(p);
    }
}

static void wait(int *p, int current)
{
    if (nt_RtlWaitOnAddress) {
        nt_RtlWaitOnAddress(p, &current, sizeof(*p), 0);
    }
}

static DWORD __stdcall threadfunc(void *arg)
{
    test_once(arg, NTHREADS);
    return 0;
}

int mainCRTStartup(void)
{
    HANDLE nt = LoadLibraryA("ntdll.dll");
    nt_RtlWaitOnAddress  = (void *)GetProcAddress(nt, "RtlWaitOnAddress");
    nt_RtlWakeAddressAll = (void *)GetProcAddress(nt, "RtlWakeAddressAll");

    HANDLE threads[64];
    void *mem = VirtualAlloc(0, 1<<12, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    for (int i = 1; i < NTHREADS; i++) {
        threads[i] = CreateThread(0, 0, threadfunc, mem, 0, 0);
    }
    test_once(mem, NTHREADS);
    for (int i = 1; i < NTHREADS; i++) {
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
    }
    return 0;
}

#elif __linux
// $ cc -pthread -o once once.c
// $ ./once || echo failed
#  include <limits.h>
#  include <linux/futex.h>
#  include <pthread.h>
#  include <stdlib.h>
#  include <sys/syscall.h>
#  include <unistd.h>

#define NTHREADS 256

static void wait(int *p, int current)
{
    syscall(SYS_futex, p, FUTEX_WAIT, current, 0, 0, 0);
}

static void wake(int *p)
{
    syscall(SYS_futex, p, FUTEX_WAKE, INT_MAX, 0, 0, 0);
}

static void *threadfunc(void *arg)
{
    test_once(arg, NTHREADS);
    return 0;
}

int main(void)
{
    pthread_t threads[NTHREADS];
    void *mem = calloc(1, 1<<12);
    for (int i = 1; i < NTHREADS; i++) {
        pthread_create(threads+i, 0, threadfunc, mem);
    }
    test_once(mem, NTHREADS);
    for (int i = 1; i < NTHREADS; i++) {
        pthread_join(threads[i], 0);
    }
    return 0;
}
#endif
