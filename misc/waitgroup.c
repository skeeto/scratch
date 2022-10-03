// Minimalist "waitgroup" implementation for C
//   $ cc -Os -pthread -o waitgroup waitgroup.c
//   $ cc -Os -o waitgroup.exe waitgroup.c -lntdll
//   $ cl /Os waitgroup.c
//
// A waitgroup is an int initialized to some non-negative value, and any
// number of threads can wait for the count to transition to zero. No
// cleanup is required. The implementation trades some performance for
// simplicity.
//
// This is free and unencumbered software released into the public domain.
#include <assert.h>

// Platform-specific synchronization primitives
static int  load(int *);           // atomic load
static int  addfetch(int *, int);  // atomic add-then-fetch
static void wait(int *, int);      // wait on change at address
static void wake(int *);           // wake all waiters by address

// Increment the counter by a non-negative quantity.
void waitgroup_add(int *wg, int delta)
{
    assert(delta >= 0);
    int c = addfetch(wg, delta);
    assert(c > 0);
}

// Decrement the counter by one, potentially waking waiters.
void waitgroup_done(int *wg)
{
    int c = addfetch(wg, -1);
    assert(c >= 0);
    if (!c) {
        wake(wg);
    }
}

// Wait until the counter is zero.
void waitgroup_wait(int *wg)
{
    for (;;) {
        int c = load(wg);
        assert(c >= 0);
        if (!c) {
            break;
        }
        wait(wg, c);
    }
}


// Implementation of platform-specific synchronization primitives
#if _WIN32
#  include <intrin.h>
#  ifdef _MSC_VER
#    pragma comment(lib, "ntdll.lib")
#  endif

// RTL functions not declared in any headers
__declspec(dllimport)
long __stdcall RtlWaitOnAddress(void *, void *, size_t, void *);
__declspec(dllimport)
long __stdcall RtlWakeAddressAll(void *);

static int load(int *p)
{
    return _InterlockedOr((long *)p, 0);
}

static int addfetch(int *p, int addend)
{
    return addend + _InterlockedExchangeAdd((long *)p, addend);
}

static void wait(int *p, int current)
{
    RtlWaitOnAddress(p, &current, sizeof(*p), 0);
}

static void wake(int *p)
{
    RtlWakeAddressAll(p);
}

#elif __linux__
#  include <limits.h>
#  include <linux/futex.h>
#  include <sys/syscall.h>
#  include <unistd.h>

static int load(int *p)
{
    return __atomic_load_n(p, __ATOMIC_SEQ_CST);
}

static int addfetch(int *p, int addend)
{
    return __atomic_add_fetch(p, addend, __ATOMIC_SEQ_CST);
}

static void wait(int *p, int current)
{
    syscall(SYS_futex, p, FUTEX_WAIT, current, 0, 0, 0);
}

static void wake(int *p)
{
    syscall(SYS_futex, p, FUTEX_WAKE, INT_MAX, 0, 0, 0);
}
#endif


// Minimalist thread creation library
void go(void (*)(void *), void *);

#if _WIN32
#include <windows.h>

struct wrap {
    void (*f)(void *);
    void *arg;
    int wg;
};

static DWORD WINAPI thread_wrap(void *wrap)
{
    struct wrap *w = wrap;
    void (*f)(void *) = w->f;
    void *arg = w->arg;
    waitgroup_done(&w->wg);
    f(arg);
    return 0;
}

void go(void (*f)(void *), void *arg)
{
    struct wrap w = {f, arg, 1};
    if (!CloseHandle(CreateThread(0, 1<<12, thread_wrap, &w, 0, 0))) {
        *(volatile int *)0 = 0;  // "panic"
    }
    waitgroup_wait(&w.wg);
}

#elif __linux__
#include <pthread.h>

struct wrap {
    void (*f)(void *);
    void *arg;
    int wg;
};

static void *wrap(void *wrap)
{
    struct wrap *w = wrap;
    void (*f)(void *) = w->f;
    void *arg = w->arg;
    waitgroup_done(&w->wg);
    f(arg);
    return 0;
}

void go(void (*f)(void *), void *arg)
{
    pthread_t thr;
    struct wrap w = {f, arg, 1};
    if (pthread_create(&thr, 0, wrap, &w)) {
        *(volatile int *)0 = 0;  // "panic"
    }
    pthread_detach(thr);
    waitgroup_wait(&w.wg);
}
#endif


// A small test to demonstrate
#include <stdint.h>
#include <stdio.h>

#define NTHREADS (1<<(12 - 4*(SIZE_MAX == UINT_MAX)))

struct share {
    int wg;
    int start;
    int sum;
};

static void worker(void *arg)
{
    struct share *s = arg;
    waitgroup_wait(&s->start);
    addfetch(&s->sum, 1);
    waitgroup_done(&s->wg);
}

int main(void)
{
    struct share share = {0, 1, 0};
    for (int i = 0; i < NTHREADS; i++) {
        waitgroup_add(&share.wg, 1);
        go(worker, &share);
    }
    waitgroup_done(&share.start);  // release the threads
    waitgroup_wait(&share.wg);
    int result = share.sum;
    printf("%d == %d\n", result, NTHREADS);
    return !(result == NTHREADS);
}
