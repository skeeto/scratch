// Zero-init, fast, fair, resource-free mutex for Windows
//
// Behaves like WaitOnAddress/WakeByAddress but manages an explicit
// waiter queue. For the same reason, it acquires no resources and so
// needs no destructor.
//
// Requires Windows 8 or later. Link with ntdll.dll and kernel32.dll.
//
// This is free and unencumbered software released into the public domain.
#include <intrin.h>
#if _MSC_VER
#  pragma comment(lib, "ntdll.lib")
#endif

__declspec(dllimport) long __stdcall NtWaitForAlertByThreadId(void *, long);
__declspec(dllimport) long __stdcall NtAlertThreadByThreadId(long);
__declspec(dllimport) long __stdcall GetCurrentThreadId(void);

struct mutex_entry {
    struct mutex_entry *next;
    long thread;
};

// A mutex must be initialized to all zeros.
#define MUTEX_INIT {0, 0, 0, 0}
typedef struct {
    struct mutex_entry *head, *tail;
    long spinlock;
    long owner;
} mutex;

void mutex_lock(mutex *m)
{
    long id = GetCurrentThreadId();

    while (_InterlockedExchange(&m->spinlock, 1)) { _mm_pause(); }
    if (!m->owner) {
        // Unlocked, grab it and return
        m->owner = id;
        _InterlockedExchange(&m->spinlock, 0);
        return;
    }

    // Append self to the end of the queue
    struct mutex_entry e = {0, id};
    if (!m->head) {
        m->head = m->tail = &e;
    } else {
        m->tail = m->tail->next = &e;
    }
    _InterlockedExchange(&m->spinlock, 0);
    NtWaitForAlertByThreadId(0, 0);
    // NOTE: Should it double-check here that it is the owner?
}

void mutex_unlock(mutex *m)
{
    while (_InterlockedExchange(&m->spinlock, 1)) { _mm_pause(); }
    struct mutex_entry *head = m->head;
    if (!head) {
        // No waiters, unlock
        m->owner = 0;
        _InterlockedExchange(&m->spinlock, 0);
    } else {
        // Pop the next waiter, pass the lock, and wake it
        long thread = m->owner = head->thread;
        m->head = head->next;
        _InterlockedExchange(&m->spinlock, 0);
        NtAlertThreadByThreadId(thread);
    }
}


// A little test to demonstrate. Since the mutex is optimized for the
// contention-free case, it is much worse under this high contention
// stress test than a non-futex mutex. Threads get in and out of the
// mutex so fast that they create an order of magnitude *extra*
// contention than a typical mutex in the same test, where a single
// thread tends to get a of work done while the other threads are slowly
// waking up.
#include <stdio.h>

__declspec(dllimport) void *__stdcall CreateThread(
    void *, size_t, long (__stdcall *)(void *), void *, long, long *);
__declspec(dllimport) long __stdcall WaitForSingleObject(void *, long);
__declspec(dllimport) char __stdcall CloseHandle(void *);

#define N (1 <<  6)
#define M (1 << 12)
static volatile int count;

struct data {
    mutex *m;
    short id;
};

static long __stdcall worker(void *arg)
{
    struct data d = *(struct data *)arg;
    for (int i = 0; i < M; i++) {
        mutex_lock(d.m);
        int c = count;
        count = c + 1;
        mutex_unlock(d.m);
    }
    return 0;
}

int main(void)
{
    mutex m = MUTEX_INIT;
    void *thr[N];
    struct data d[N];
    for (int i = 0; i < N; i++) {
        d[i].m = &m;
        d[i].id = i;
        thr[i] = CreateThread(0, 0, worker, d+i, 0, 0);
    }
    for (int i = 0; i < N; i++) {
        WaitForSingleObject(thr[i], -1);
        CloseHandle(thr[i]);
    }
    int snapshot = count;
    printf("%d == %d (%d)\n", snapshot, M*N, snapshot==M*N);
}
