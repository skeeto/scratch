// Another solver for "Ada and Friends" (ADAFRIEN)
// Using a hash-trie instead of an MSI hash table. See adafrien.c.
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>

#define new(a, t, n)  (t *)alloc(a, sizeof(t), _Alignof(t), n)

typedef uint8_t   u8;
typedef int32_t   b32;
typedef int32_t   i32;
typedef int64_t   i64;
typedef uint64_t  u64;
typedef ptrdiff_t size;
typedef uintptr_t uptr;
typedef char      byte;

static byte *alloc(byte **p, size objsize, size align, size count)
{
    *p += -(uptr)*p & (align - 1);
    byte *r = *p;
    *p += objsize * count;
    return r;
}

static b32 whitespace(u8 c)
{
    switch (c) {
    case '\t': case '\n': case '\r': case ' ':
        return 1;
    }
    return 0;
}

typedef struct {
    u8  *data;
    size len;
} s8;

static s8 s8span(u8 *beg, u8 *end)
{
    s8 r = {0};
    r.data = beg;
    r.len = end - beg;
    return r;
}

static u64 s8hash(s8 s)
{
    u64 h = 0x100;
    for (size i = 0; i < s.len; i++) {
        h ^= s.data[i];
        h *= 1111111111111111111u;
    }
    return h;
}

static b32 s8equal(s8 a, s8 b)
{
    if (a.len != b.len) {
        return 0;
    }
    for (size i = 0; i < a.len; i++) {
        if (a.data[i] != b.data[i]) {
            return 0;
        }
    }
    return 1;
}

static i32 i32parse(s8 s)
{
    i32 r = 0;
    for (size i = 0; i < s.len; i++) {
        i32 d = s.data[i] - '0';
        r = r*10 + d;
    }
    return r;
}

typedef struct {
    s8 head;
    s8 tail;
} token;

static token tokenize(s8 s)
{
    token r = {0};
    for (; s.len && whitespace(*s.data); s.data++, s.len--) {}
    r.head = s;
    r.tail.data = s.data;
    for (size i = 0; i < s.len; i++) {
        if (whitespace(r.head.data[i])) {
            r.head.len = i;
            r.tail.data += i + 1;
            r.tail.len = s.len - i - 1;
            break;
        }
    }
    return r;
}

typedef struct friend friend;
struct friend {
    friend *child[4];
    s8      name;
    i64     cost;
    friend *next;
};

static friend *upsert(friend **m, s8 name, byte **heap)
{
    u64 h = s8hash(name);
    for (; *m; h <<= 2) {
        if (s8equal((*m)->name, name)) {
            return *m;
        }
        m = (*m)->child + (h>>62);
    }
    *m = new(heap, friend, 1);
    (*m)->name = name;
    return *m;
}

static friend *sort(friend *head)
{
    if (!head || !head->next) {
        return head;
    }

    size len = 0;
    friend *tail = head;
    friend *last = head;
    for (friend *f = head; f; f = f->next, len++) {
        if (len & 1) {
            last = tail;
            tail = tail->next;
        }
    }

    last->next = 0;
    head = sort(head);
    tail = sort(tail);

    friend  *rhead = 0;
    friend **rtail = &rhead;
    while (head && tail) {
        if (head->cost > tail->cost) {
            *rtail = head;
            head = head->next;
        } else {
            *rtail = tail;
            tail = tail->next;
        }
        rtail = &(*rtail)->next;
    }
    *rtail = head ? head : tail;
    return rhead;
}

static s8 i64print(i64 x, byte **heap)
{
    u8 *buf = new(heap, u8, 32);
    u8 *end = buf + 32;
    u8 *beg = end;
    *--beg = '\n';
    do {
        *--beg = '0' + (u8)(x%10);
    } while (x /= 10);
    return s8span(beg, end);
}

static s8 solve(byte *heap, s8 input)
{
    token token = {0};
    token.tail = input;

    token = tokenize(token.tail);
    i32 nparty = i32parse(token.head);

    token = tokenize(token.tail);
    i32 ndrop = i32parse(token.head);

    friend  *head = 0;
    friend **tail = &head;
    for (i32 i = 0; i < nparty; i++) {
        token = tokenize(token.tail);
        s8 who = token.head;
        token = tokenize(token.tail);
        i32 cost = i32parse(token.head);
        friend *f = upsert(&head, who, &heap);
        if (!f->cost) {
            *tail = f;
            tail = &f->next;
        }
        f->cost += cost;
    }

    i64 save = 0;
    for (friend *f = sort(head); f && ndrop; f = f->next, ndrop--) {
        save += f->cost;
    }
    return i64print(save, &heap);
}


#ifdef _WIN32
// $ cc -nostartfiles -fno-builtin -o adafrien2.exe adafrien2.c

#define W32(r) __declspec(dllimport) r __stdcall
W32(void) ExitProcess(i32);
W32(i32)  GetStdHandle(i32);
W32(b32)  ReadFile(uptr, u8 *, i32, i32 *, void *);
W32(b32)  WriteFile(uptr, u8 *, i32, i32 *, void *);

static s8 loadstdin(byte **heap)
{
    s8 r = {0};
    r.data = (u8 *)*heap;
    i32 stdin = GetStdHandle(-10);
    for (;;) {
        i32 len;
        if (!ReadFile(stdin, r.data+r.len, 1<<20, &len, 0) || !len) {
            *heap += r.len;
            return r;
        }
        r.len += len;
    }
}

__attribute((force_align_arg_pointer))
void mainCRTStartup(void)
{
    static byte mem[1<<25];
    byte *heap = mem;
    asm ("" : "+r"(heap));
    s8 input = loadstdin(&heap);
    s8 r = solve(heap, input);
    i32 stdout = GetStdHandle(-11);
    i32 dummy;
    i32 err = !WriteFile(stdout, r.data, (i32)r.len, &dummy, 0);
    ExitProcess(err);
}
#endif
