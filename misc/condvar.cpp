// Condition variables built on futexes
//
// $ cc -nostartfiles -o condvar.exe condvar.cpp -lsynchronization
// $ ./condvar.exe && echo success
//
// Requires GCC or Clang and 64-bit Windows 7 or later.
//
// The mutex avoids a system call if there are no waiters (see mutex.c),
// but the condition variable is naive and always signals the futex. It
// uses a 64-bit futex to avoid potential wraparound of the condition
// variable, e.g. a producer makes a full lap between consumer peeks,
// causing the consumer to miss a wake-up. In practice lapping a 64-bit
// integer is infeasible. This 64-bit futex makes porting to other more
// difficult.
//
// There's no reason whatsoever to use this implementation in a real
// application. SRW locks in kernel32.dll are better in every way. See
// https://nullprogram.com/blog/2024/10/03/. This program is merely an
// experiment and exercise.
//
// This is free and unencumbered software released into the public domain.

#define assert(c)  while (!(c)) __builtin_trap()

using b32 = signed;
using i32 = signed;
using u32 = unsigned;
using i64 = long long;
using uz  = decltype(sizeof(0));

enum Obj : uz;

#define W32(r, p) extern "C" __declspec(dllimport) r __stdcall p noexcept
W32(b32,  CloseHandle(Obj));
W32(Obj,  CreateThread(uz, uz, i32(__stdcall *)(void *), void *, i32, uz));
W32(void, ExitProcess(i32));
W32(b32,  WaitOnAddress(void *, void *, uz, i32));
W32(void, WakeByAddressAll(void *));
W32(void, WakeByAddressSingle(void *));

template<typename T>
static T load(T *p)
{
    return __atomic_load_n(p, __ATOMIC_RELAXED);
}

template<typename T>
static T incr(T *p, T v)
{
    return __atomic_add_fetch(p, v, __ATOMIC_RELAXED);
}

template<typename T>
static T cas(T *p, T prev, T next)
{
    i32 pass = __ATOMIC_SEQ_CST;
    i32 fail = __ATOMIC_RELAXED;
    __atomic_compare_exchange_n(p, &prev, next, 0, pass, fail);
    return prev;
}

template<typename T>
static T exchange(T *p, T v)
{
    return __atomic_exchange_n(p, v, __ATOMIC_SEQ_CST);
}

template<typename T>
static b32 wait(T *p, T e, i32 ms = -1)
{
    return WaitOnAddress(p, &e, sizeof(T), ms);
}

template<typename T>
static void wakeone(T *p)
{
    WakeByAddressSingle(p);
}

template<typename T>
static void wakeall(T *p)
{
    WakeByAddressAll(p);
}

enum Mutex : i32 {MUTEX_UNLOCKED, MUTEX_LOCKED, MUTEX_SLEEPING};

static void lock(Mutex *m)
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

static void unlock(Mutex *m)
{
    if (exchange(m, MUTEX_UNLOCKED) == MUTEX_SLEEPING) {
        wakeone(m);
    }
}

struct Guard {
    Mutex *m;
    Guard(Mutex *m) : m{m} { lock(m); }
    ~Guard()               { unlock(m); }
};

enum Cond : i64;

static void wait(Cond *cv, Mutex *m, i32 ms = -1)
{
    Cond phase = load(cv);
    unlock(m);
    wait(cv, phase, ms);
    lock(m);
}

static void signal(Cond *cv)
{
    incr(cv, Cond(1));
    wakeone(cv);
}

static void broadcast(Cond *cv)
{
    incr(cv, Cond(1));
    wakeall(cv);
}

// Test: build things out of condition variables and use them

struct Barrier {
    Cond  done;
    i32   count;
    Mutex m;
};

void wait(Barrier *b)
{
    Guard g(&b->m);
    if (!--b->count) {
        broadcast(&b->done);
    } else {
        while (b->count) {
            wait(&b->done, &b->m);
        }
    }
}

template<typename T>
struct Optional {
    T   value;
    b32 ok;
};

template<typename T, i32 E = 8>
struct Queue {
    Cond empty;
    Cond full;
    T    buf[1u<<E];
    u32  head;
    u32  tail;
    b32  done;
    Mutex m;
};

template<typename T, i32 E>
void close(Queue<T, E> *q)
{
    Guard g(&q->m);
    q->done = 1;
    broadcast(&q->empty);
}

template<typename T, i32 E>
void push(Queue<T, E> *q, T v)
{
    Guard g(&q->m);
    u32 mask = (1u<<E) - 1;
    while (q->head == q->tail+mask) {
        wait(&q->full, &q->m);
    }
    q->buf[q->head++&mask] = v;
    signal(&q->empty);
}

template<typename T, i32 E>
Optional<T> pop(Queue<T, E> *q)
{
    Guard g(&q->m);
    while (q->head==q->tail && !q->done) {
        wait(&q->empty, &q->m);
    }

    if (q->head == q->tail) {
        return {};
    }

    signal(&q->full);
    u32 mask = (1u<<E) - 1;
    return {q->buf[q->tail++&mask], 1};
}

struct Test {
    i64        total;
    Queue<i32> queue;
    Barrier    init;
    Cond       done;
    b32        ready;
    i32        nthreads;
    Mutex      m;
};

static i32 __stdcall worker(void *arg)
{
    Test *t = (Test *)arg;
    wait(&t->init);

    i64 total = 0;
    for (;;) {
        auto [value, ok] = pop(&t->queue);
        if (!ok) break;
        total += value;
    }

    Guard g(&t->m);
    t->total += total;
    if (!--t->nthreads) {
        signal(&t->done);
    }
    return 0;
}

extern "C" i32 __stdcall mainCRTStartup(void *)
{
    enum {
        N = 32,
        C = 1000000,
    };

    Test t = {};
    t.init.count = N;
    t.nthreads = N;

    for (i32 i = 0; i < N; i++) {
        Obj h = CreateThread(0, 0, worker, &t, 0, 0);
        CloseHandle(h);
    }

    i64 total = 0;
    for (i32 i = 0; i < C; i++) {
        total += i + 1;
        push(&t.queue, i + 1);
    }
    close(&t.queue);

    while (t.nthreads) {
        wait(&t.done, &t.m);
    }
    assert(t.total == total);

    ExitProcess(0);
    __builtin_unreachable();
}
