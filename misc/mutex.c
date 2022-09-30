// Zero-init, fast, fair, resource-free futex-based mutex
// This is free and unencumbered software released into the public domain.

// A mutex may be initialized to either unlocked (0) or locked (1).
typedef enum {MUTEX_UNLOCKED=0, MUTEX_LOCKED, MUTEX_SLEEPING} mutex;
void mutex_lock(mutex *);
void mutex_unlock(mutex *);


// Primitive, platform-specific operations
static void wait(mutex *, mutex);
static void wake(mutex *);
static mutex exchange(mutex *, mutex);
static mutex cas(mutex *, mutex old, mutex new);

#if _WIN32
// Requires Windows 8 or later. Link with ntdll.dll.
#include <intrin.h>
#  if _MSC_VER
#    pragma comment(lib, "ntdll.lib")
#  endif

__declspec(dllimport) long __stdcall RtlWaitOnAddress(void *, void *, size_t, void *);
__declspec(dllimport) long __stdcall RtlWakeAddressSingle(void *);

static void wait(mutex *m, mutex v)
{
    RtlWaitOnAddress(m, &v, sizeof(*m), 0);
}

static void wake(mutex *m)
{
    RtlWakeAddressSingle(m);
}

static mutex exchange(mutex *m, mutex v)
{
    return _InterlockedExchange((long *)m, v);
}

static mutex cas(mutex *m, mutex old, mutex new)
{
    return _InterlockedCompareExchange((long *)m, new, old);
}

#elif __linux__
// Requires Linux 2.6.0 or later.
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

static void wait(mutex *m, mutex v)
{
    syscall(SYS_futex, m, FUTEX_WAIT, v, 0, 0, 0);
}

static void wake(mutex *m)
{
    syscall(SYS_futex, m, FUTEX_WAKE, 1, 0, 0, 0);
}

static mutex exchange(mutex *m, mutex v)
{
    return __atomic_exchange_n(m, v, __ATOMIC_SEQ_CST);
}

static mutex cas(mutex *m, mutex old, mutex new)
{
    __atomic_compare_exchange_n(
        m, &old, new, 1, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST
    );
    return old;
}
#endif


// Mutex implementation using the above abstract operations

void mutex_lock(mutex *m)
{
    switch (cas(m, MUTEX_UNLOCKED, MUTEX_LOCKED)) {
    case MUTEX_UNLOCKED:
        return;
    case MUTEX_LOCKED:
        cas(m, MUTEX_LOCKED, MUTEX_SLEEPING);
        // fallthrough
    case MUTEX_SLEEPING:
        do {
            wait(m, MUTEX_SLEEPING);
        } while (exchange(m, MUTEX_SLEEPING) != MUTEX_UNLOCKED);
    }
}

void mutex_unlock(mutex *m)
{
    if (exchange(m, MUTEX_UNLOCKED) == MUTEX_SLEEPING) {
        wake(m);
    }
}


// Simple, portable threading interface
//   thread thread_create(void (*)(void *), void *);
//   void   thread_join(thread);

#if _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef HANDLE thread;
struct thread_wrap {
    void (*f)(void *);
    void *arg;
    mutex done;
};

static DWORD WINAPI thread_wrap(void *wrap)
{
    struct thread_wrap *w = wrap;
    void (*f)(void *) = w->f;
    void *arg = w->arg;
    mutex_unlock(&w->done);
    f(arg);
    return 0;
}

static thread thread_create(void (*f)(void *), void *arg)
{
    struct thread_wrap w = {f, arg, MUTEX_LOCKED};
    HANDLE h = CreateThread(0, 0, thread_wrap, &w, 0, 0);
    mutex_lock(&w.done);
    return h;
}

static void thread_join(thread t)
{
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}

#elif __linux__
#include <pthread.h>

typedef pthread_t thread;
struct thread_wrap {
    void (*f)(void *);
    void *arg;
    mutex done;
};

static void *thread_wrap(void *wrap)
{
    struct thread_wrap *w = wrap;
    void (*f)(void *) = w->f;
    void *arg = w->arg;
    mutex_unlock(&w->done);
    f(arg);
    return 0;
}

static thread thread_create(void (*f)(void *), void *arg)
{
    pthread_t thr;
    struct thread_wrap w = {f, arg, MUTEX_LOCKED};
    pthread_create(&thr, 0, thread_wrap, &w);
    mutex_lock(&w.done);
    return thr;
}

static void thread_join(thread t)
{
    pthread_join(t, 0);
}
#endif


// Some tests to demonstate the mutex

#if 1
#include <stdio.h>

#define N (1 <<  6)
#define M (1 << 16)

static volatile int count;

static void worker(void *m)
{
    for (int i = 0; i < M; i++) {
        mutex_lock(m);
        int c = count;  // note: volatile avoids to atomic increment
        count = c + 1;
        mutex_unlock(m);
    }
}

int main(void)
{
    mutex m = 0;
    thread thr[N];
    for (int i = 0; i < N; i++) {
        thr[i] = thread_create(worker, &m);
    }
    for (int i = 0; i < N; i++) {
        thread_join(thr[i]);
    }
    printf("%d == %d\n", count, N*M);
}

#else
#include <stdio.h>
#include <pthread.h>

struct job {
    mutex *m;
    int id;
};

static void *worker(void *m)
{
    struct job *j = m;
    mutex_lock(j->m);
    mutex_unlock(j->m);
    return 0;
}

int main(void)
{
    mutex m = 0;
    pthread_t thr[3];
    struct job j[3];
    for (int i = 0; i < 3; i++) {
        j[i].m = &m;
        j[i].id = i;
        pthread_create(thr+i, 0, worker, j+i);
    }
    for (int i = 0; i < 3; i++) {
        pthread_join(thr[i], 0);
    }
}
#endif
