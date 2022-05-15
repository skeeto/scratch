// A lock-free, concurrent, generic queue in 32 bits
//
// This is a bit of a mess since I wanted to hit many different combinations
// of implementations with the same code, especially under TSan:
//
// impl  threads  atom target cmd
// ----  -------  ---- ------ ----------
// GCC   pthreads C11  spsc   gcc -O3 -DNTHR=1 -DPTHREADS queue.c
// GCC   pthreads GNU  spsc   gcc -O3 -std=c99 -DNTHR=1 -DPTHREADS queue.c
// GCC   win32    C11  spsc   gcc -O3 -DNTHR=1 queue.c
// GCC   win32    GNU  spsc   gcc -O3 -std=c99 -DNTHR=1 queue.c
// GCC   pthreads C11  spmc   gcc -O3 -DNTHR=2 -DPTHREADS queue.c
// GCC   pthreads GNU  spmc   gcc -O3 -std=c99 -DNTHR=2 -DPTHREADS queue.c
// GCC   win32    C11  spmc   gcc -O3 -DNTHR=2 queue.c
// GCC   win32    GNU  spmc   gcc -O3 -std=c99 -DNTHR=2 queue.c
// Clang pthreads C11  spsc   clang -O3 -DNTHR=1 -DPTHREADS queue.c
// Clang pthreads GNU  spsc   clang -O3 -std=c99 -DNTHR=1 -DPTHREADS queue.c
// Clang win32    C11  spsc   clang -O3 -DNTHR=1 queue.c
// Clang win32    GNU  spsc   clang -O3 -std=c99 -DNTHR=1 queue.c
// Clang pthreads C11  spmc   clang -O3 -DNTHR=2 -DPTHREADS queue.c
// Clang pthreads GNU  spmc   clang -O3 -std=c99 -DNTHR=2 -DPTHREADS queue.c
// Clang win32    C11  spmc   clang -O3 -DNTHR=2 queue.c
// Clang win32    GNU  spmc   clang -O3 -std=c99 -DNTHR=2 queue.c
// MSC   win32    MSC  spsc   cl /Ox /DNTHR=1 queue.c
// MSC   win32    MSC  spmc   cl /Ox /DNTHR=2 queue.c
//
// Also multiply that by multiple operating systems (Linux, Windows, BSD).
//
// Ref: https://nullprogram.com/blog/2022/05/14/
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <stdint.h>

#define NVALS 1000000
#define QEXP  6
#ifndef NTHR
#  define NTHR  1
#endif

// Threads
#if _WIN32 && !defined(PTHREADS)
#  include <windows.h>
#  include <process.h>
#  define WHAT_THREADS "win32"
   typedef HANDLE pthread_t;
#  define pthread_create(t,p,f,a) \
       *(t) = (HANDLE)_beginthreadex(0, 0, (void *)f, a, 0, 0)
#  define pthread_join(t,r) \
       do { \
           WaitForSingleObject(t, INFINITE); \
           CloseHandle(t); \
       } while (0)
#else
#  include <pthread.h>
#  define WHAT_THREADS "pthreads"
#endif

// Atomics
#if __STDC_VERSION__ >= 201112L && !__STDC_NO_ATOMICS
#  include <stdatomic.h>
#  define WHAT_ATOMICS "C11"
#elif __GNUC__
#  define WHAT_ATOMICS "GNUC"
#  define ATOMIC_VENDOR 1
#  define _Atomic
#  define ATOMIC_LOAD(q)       __atomic_load_n(q, __ATOMIC_ACQUIRE)
#  define ATOMIC_RLOAD(q)      __atomic_load_n(q, __ATOMIC_RELAXED)
#  define ATOMIC_STORE(q, v)   __atomic_store_n(q, v, __ATOMIC_RELEASE)
#  define ATOMIC_ADD(q, c)     __atomic_add_fetch(q, c, __ATOMIC_RELEASE)
#  define ATOMIC_AND(q, m)     __atomic_and_fetch(q, m, __ATOMIC_RELEASE)
#  define ATOMIC_CAS(q, e, d)  __atomic_compare_exchange_n( \
        q, e, d, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED)
#elif _MSC_VER
#  define WHAT_ATOMICS "MSC"
#  define ATOMIC_VENDOR 1
#  include <winnt.h>
#  define _Atomic volatile
#  define ATOMIC_LOAD(a)       *(a)      // MSC volatile has atomic semantics
#  define ATOMIC_RLOAD(a)      *(a)      //
#  define ATOMIC_STORE(a, v)   *(a) = v  // "
#  define ATOMIC_ADD(a, c)     InterlockedAdd(a, c)
#  define ATOMIC_AND(a, m)     InterlockedAnd(a, m)
#  define ATOMIC_CAS(a, e, d)  (InterlockedCompareExchange(a, d, *e) == *e)
#endif

// Return the array index for then next value to be pushed. The size of this
// array must be (1 << exp) elements. Write the value into this array index,
// then commit it. With a single-consumer queue, this element store need not
// be atomic. The value will appear in the queue after the commit. Returns
// -1 if the queue is full.
static int
queue_push(_Atomic uint32_t *q, int exp)
{
    #if ATOMIC_VENDOR
    uint32_t r = ATOMIC_LOAD(q);
    #else
    uint32_t r = *q;
    #endif
    int mask = (1u << exp) - 1;
    int head = r     & mask;
    int tail = r>>16 & mask;
    int next = (head + 1u) & mask;
    if (r & 0x8000) {  // avoid overflow on commit
        #if ATOMIC_VENDOR
        ATOMIC_AND(q, ~0x8000);
        #else
        *q &= ~0x8000;
        #endif
    }
    return next == tail ? -1 : head;
}

// Commits and completes the push operation. Do this after storing into the
// array. This operation cannot fail.
static void
queue_push_commit(_Atomic uint32_t *q)
{
    #if ATOMIC_VENDOR
    ATOMIC_ADD(q, 1);
    #else
    *q += 1;
    #endif
}

// Return the array index for the next value to be popped. The size of this
// array must be (1 << exp) elements. Read from this array index, then
// commit the pop. This element load need not be atomic. The value will be
// removed from the queue after the commit. Returns -1 if the queue is
// empty.
static int
queue_pop(_Atomic uint32_t *q, int exp)
{
    #if ATOMIC_VENDOR
    uint32_t r = ATOMIC_LOAD(q);
    #else
    uint32_t r = *q;
    #endif
    int mask = (1u << exp) - 1;
    int head = r     & mask;
    int tail = r>>16 & mask;
    return head == tail ? -1 : tail;
}

// Commits and completes the pop operation. Do this after loading from the
// array. This operation cannot fail.
static void
queue_pop_commit(_Atomic uint32_t *q)
{
    #if ATOMIC_VENDOR
    ATOMIC_ADD(q, 0x10000);
    #else
    *q += 0x10000;
    #endif
}

// Like queue_pop() but for multiple-consumer queues. The element load must
// be atomic since it is concurrent with the producer's push, though it can
// use a relaxed memory order. The loaded value must not be used unless the
// commit is successful. Stores a temporary "save" to be used at commit.
static int
queue_mpop(_Atomic uint32_t *q, int exp, uint32_t *save)
{
    #if ATOMIC_VENDOR
    uint32_t r = *save = ATOMIC_LOAD(q);
    #else
    uint32_t r = *save = *q;
    #endif
    int mask = (1u << exp) - 1;
    int head = r     & mask;
    int tail = r>>16 & mask;
    return head == tail ? -1 : tail;
}

// Like queue_pop_commit() but for multiple-consumer queues. It may fail if
// another consumer pops concurrently, in which case the pop must be retried
// from the beginning.
static _Bool
queue_mpop_commit(_Atomic uint32_t *q, uint32_t save)
{
    #if ATOMIC_VENDOR
    return ATOMIC_CAS(q, &save, save+0x10000);
    #else
    return atomic_compare_exchange_strong(q, &save, save+0x10000);
    #endif
}

struct task {
    _Atomic uint32_t *q;
    #if NTHR > 1
    _Atomic
    #endif
    uint64_t *slots;
    uint64_t result;
};

static void *
worker(void *arg)
{
    struct task *t = arg;
    _Atomic uint32_t *q = t->q;
    uint64_t sum = 0;
    for (;;) {
        int i;
        uint64_t v;
        #if NTHR == 1
        do {
            i = queue_pop(q, QEXP);
        } while (i < 0);
        v = t->slots[i];
        queue_pop_commit(q);
        #else
        uint32_t save;
        do {
            do {
                i = queue_mpop(q, QEXP, &save);
            } while (i < 0);
            #if ATOMIC_VENDOR
            v = ATOMIC_RLOAD(t->slots+i);
            #else
            v = atomic_load_explicit(t->slots+i, memory_order_relaxed);
            #endif
        } while (!queue_mpop_commit(q, save));
        #endif

        if (!v) {
            t->result = sum;
            return 0;
        }
        sum += v;
    }
}

int
main(void)
{
    printf("Using %d "WHAT_THREADS" threads, "WHAT_ATOMICS" atomics\n", NTHR);

    _Atomic uint32_t q = 0;
    pthread_t thr[NTHR];
    struct task tasks[NTHR];
    #if NTHR > 1
    _Atomic
    #endif
    uint64_t slots[1<<QEXP];

    for (int n = 0; n < NTHR; n++) {
        tasks[n].q = &q;
        tasks[n].slots = slots;
        pthread_create(thr+n, 0, worker, tasks+n);
    }

    uint64_t sum = 0;
    for (int n = 0; n < NVALS; n++) {
        uint64_t x = -n - 1;
        x *= 1111111111111111111U; x ^= x >> 32;
        x *= 1111111111111111111U; x ^= x >> 32;
        int i;
        do {
            i = queue_push(&q, QEXP);
        } while (i < 0);
        sum += x;
        #if NTHR == 1
        slots[i] = x;
        #elif ATOMIC_VENDOR
        ATOMIC_STORE(slots+i, x);
        #else
        atomic_store_explicit(slots+i, x, memory_order_relaxed);
        #endif
        queue_push_commit(&q);
    }
    printf("%016llx\n", (unsigned long long)sum);

    for (int n = 0; n < NTHR; n++) {
        int i;
        do {
            i = queue_push(&q, QEXP);
        } while (i < 0);
        slots[i] = 0;
        queue_push_commit(&q);
    }

    sum = 0;
    for (int n = 0; n < NTHR; n++) {
        pthread_join(thr[n], 0);
        sum += tasks[n].result;
    }
    printf("%016llx\n", (unsigned long long)sum);
}
