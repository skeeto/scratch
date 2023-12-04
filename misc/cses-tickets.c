// Concert Tickets (programming challenge)
// https://cses.fi/problemset/task/1091
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>

#define assert(c)       while (!(c)) __builtin_unreachable()
#define countof(a)      (size)(sizeof(a)/sizeof(*(a)))
#define new(h, t, n, b) (t *)alloc(h, sizeof(t), n, b)
#define s8(s)           (s8){(u8 *)s, countof(s)-1}

#define UNINIT 1

typedef uint8_t   u8;
typedef int32_t   b32;
typedef int32_t   i32;
typedef char      byte;
typedef uintptr_t uptr;
typedef ptrdiff_t size;

static b32 fullwrite(u8 *buf, i32 len);

typedef struct {
    u8  *data;
    size len;
} s8;

static s8 s8span(u8 *beg, u8 *end)
{
    s8 r = {0};
    r.data = beg;
    r.len = beg ? end-beg: 0;
    return r;
}

static byte *alloc(byte **heap, size objsize, size count, b32 noinit)
{
    size total = objsize* count;
    byte *r = *heap -= total;
    if (!noinit) {
        for (size i = 0; i < total; i++) {
            r[i] = 0;
        }
    }
    return r;
}

static b32 digit(u8 c)
{
    return (unsigned)c-'0' <= 9;
}

typedef struct {
    i32 value;
    s8  remain;
} i32parsed;

static i32parsed parse(s8 s)
{
    i32parsed r = {};
    u8 *p = s.data;
    u8 *e = s.data + s.len;
    for (; !digit(*p); p++) {}
    while (p < e) {
        if (!digit(*p)) {
            break;
        }
        r.value = r.value*10 + *p++ - '0';
    }
    r.remain.data = p;
    r.remain.len = e - p;
    return r;
}

static void sorti32(i32 *nums, size len, i32 shift)
{
    enum { EXP = 7 };

    if (len < 1<<8) {
        // Insertion sort for small inputs
        for (i32 i = 1; i < (i32)len; i++) {
            for (i32 j = i; j>0 && nums[j-1]>nums[j]; j--) {
                i32 swap = nums[j-1];
                nums[j-1] = nums[j];
                nums[j] = swap;
            }
        }
        return;
    }

    // First pass: count each bin size
    i32 mask  = (1<<EXP) - 1;
    i32 spare = EXP - (32%EXP + EXP)%EXP;
    size fill[1<<EXP] = {0};
    for (size i = 0; i < len; i++) {
        i32 bin = (i32)(nums[i]>>(32 - spare - shift)) & mask;
        fill[bin]++;
    }

    // Locate bin ranges in the sorted array
    size ends[1<<EXP];
    size accum = 0;
    for (i32 b = 0; b < 1<<EXP; b++) {
        size beg = accum;
        accum   += fill[b];
        ends[b]  = accum;
        fill[b]  = beg;
    }

    // Second pass: move elements into allotted bins
    for (i32 b = 0; b < 1<<EXP; b++) {
        for (size i = fill[b]; i < ends[b];) {
            i32 bin = (i32)(nums[i]>>(32 - spare - shift)) & mask;
            if (bin == b) {
                i++;
            } else {
                i32 swap = nums[fill[bin]];
                nums[fill[bin]++] = nums[i];
                nums[i] = swap;
            }
        }
    }

    // Recursively sort each bin on the next digit
    if (shift < 32-spare) {
        for (i32 b = 0; b < 1<<EXP; b++) {
            size beg = b>0 ? ends[b-1] : 0;
            sorti32(nums+beg, ends[b]-beg, shift+EXP);
        }
    }
}

typedef struct {
    i32 cost;
    i32 count;
} ticket;

static i32 find(ticket *t, i32 len, i32 cost)
{
    i32 lo = 0;
    i32 hi = len - 1;
    while (lo <= hi) {
        i32 mid = (hi + lo) / 2;
        if (cost == t[mid].cost) {
            if (t[mid].count) {
                return mid;
            }
            hi = mid - 1;
        } else if (cost < t[mid].cost) {
            hi = mid - 1;
        } else if (cost > t[mid].cost) {
            lo = mid + 1;
        }
    }
    i32 i = hi>lo ? hi-1 : lo-1;
    for (; i>=0 && !t[i].count; i--) {}
    return i;
}

typedef struct {
    u8 *buf;
    i32 len;
    i32 cap;
    i32 err;
} bufout;

static bufout *newbufout(byte **heap)
{
    bufout *o = new(heap, bufout, 1, 0);
    o->cap = 1<<14;
    o->buf = new(heap, u8, o->cap, UNINIT);
    return o;
}

static void flush(bufout *o)
{
    if (!o->err && o->len) {
        o->err = !fullwrite(o->buf, o->len);
        o->len = 0;
    }
}

static void print(bufout *o, s8 s)
{
    u8 *buf = s.data;
    u8 *end = s.data + s.len;
    while (!o->err && buf<end) {
        i32 avail = o->cap - o->len;
        i32 count = end-buf<avail ? (i32)(end-buf) : avail;
        u8 *dst = o->buf + o->len;
        for (i32 i = 0; i < count; i++) {
            dst[i] = buf[i];
        }
        buf += count;
        o->len += count;
        if (o->len == o->cap) {
            flush(o);
        }
    }
}

static void printi32(bufout *o, i32 x)
{
    u8  buf[16];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    do {
        *--beg = (u8)(x%10) + '0';
    } while (x /= 10);
    print(o, s8span(beg, end));
}

static i32 compress(ticket *t, i32 len)
{
    i32 out = 0;
    for (i32 i = 0; i < len; i++) {
        if (t[i].count) {
            t[out++] = t[i];
        }
    }
    return out;
}

static b32 solve(s8 input, byte *heap)
{
    bufout *stdout = newbufout(&heap);

    i32parsed r = {0};
    r.remain = input;

    r = parse(r.remain);
    i32 ncosts = r.value;
    i32 *costs = new(&heap, i32, ncosts, UNINIT);
    assert(ncosts >= 1);
    assert(ncosts <= 200000);

    r = parse(r.remain);
    i32 ncustomers = r.value;
    i32 *customers = new(&heap, i32, ncustomers, UNINIT);
    assert(ncustomers >= 1);
    assert(ncustomers <= 200000);

    for (i32 i = 0; i < ncosts; i++) {
        r = parse(r.remain);
        costs[i] = r.value;
        assert(costs[i] >= 1);
        assert(costs[i] <= 1000000000);
    }
    sorti32(costs, ncosts, 0);

    i32 ntickets = 1;
    ticket *tickets = new(&heap, ticket, ncosts, UNINIT);
    tickets[0].cost = costs[0];
    tickets[0].count = 1;
    for (i32 i = 1; i < ncosts; i++) {
        if (costs[i] == tickets[ntickets-1].cost) {
            tickets[ntickets-1].count++;
        } else {
            tickets[ntickets].cost = costs[i];
            tickets[ntickets++].count = 1;
        }
    }

    i32 max = 0;
    for (i32 i = 0; i < ncustomers; i++) {
        r = parse(r.remain);
        customers[i] = r.value;
        assert(customers[i] >= 1);
        assert(customers[i] <= 1000000000);
        max = customers[i]>max ? customers[i] : max;
    }

    for (; ntickets && max<tickets[ntickets-1].cost; ntickets--) {}

    i32 holes = 0;
    for (i32 i = 0; i < ncustomers; i++) {
        i32 best = find(tickets, ntickets, customers[i]);
        if (best < 0) {
            print(stdout, s8("-1\n"));
        } else {
            printi32(stdout, tickets[best].cost);
            print(stdout, s8("\n"));
            holes += !--tickets[best].count;
            if (holes > 1<<8) {
                ntickets = compress(tickets, ntickets);
                holes = 0;
            }
        }
    }

    flush(stdout);
    return !stdout->err;
}


#if __cplusplus
#include <unistd.h>
#include <stdlib.h>

static b32 fullwrite(u8 *buf, i32 len)
{
    for (size off = 0; off < len;) {
        size r = write(1, buf+off, len-off);
        if (r < 1) {
            return 0;
        }
        off += r;
    }
    return 1;
}

int main()
{
    size cap = 1<<24;
    s8 buf = {0};
    buf.data = (u8 *)malloc(cap);
    for (;;) {
        size r = read(0, buf.data+buf.len, cap-buf.len);
        if (r < 1) {
            break;
        }
        buf.len += r;
    }
    size heapcap = 1<<28;
    return !solve(buf, (char *)malloc(heapcap)+heapcap);
}

#elif _WIN32
#define W32(r) __declspec(dllimport) r __stdcall
W32(void)   ExitProcess(i32);
W32(i32)    GetStdHandle(i32);
W32(b32)    ReadFile(uptr, u8 *, i32, i32 *, uptr);
W32(byte *) VirtualAlloc(byte *, size, i32, i32);
W32(b32)    WriteFile(uptr, u8 *, i32, i32 *, uptr);

static b32 fullwrite(u8 *buf, i32 len)
{
    i32 stdout = GetStdHandle(-11);
    return WriteFile(stdout, buf, len, &len, 0);
}

void mainCRTStartup(void)
{
    i32 len = 0;
    i32 cap = 1<<28;
    byte *mem = VirtualAlloc(0, cap, 0x3000, 4);

    s8 buf = {0};
    buf.data = (u8 *)mem;
    i32 stdin = GetStdHandle(-10);
    ReadFile(stdin, buf.data, cap, &len, 0);
    buf.len = len;

    b32 r = solve(buf, mem+cap);
    ExitProcess(!r);
}

#elif __linux
asm (
    "        .globl _start\n"
    "_start: call entrypoint\n"
);

static b32 fullwrite(u8 *buf, i32 len)
{
    for (size off = 0; off < len;) {
        size r;
        asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(1), "D"(1), "S"(buf+off), "d"(len-off)
            : "rcx", "r11", "memory"
        );
        if (r < 1) {
            return 0;
        }
        off += r;
    }
    return 1;
}

void entrypoint(void)
{
    static byte mem[1<<28];
    char *heap = mem + countof(mem);
    asm ("" : "+r"(heap));

    s8 buf = {0};
    buf.data = (u8 *)mem;
    for (;;) {
        size r;
        asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(0), "D"(0), "S"(buf.data+buf.len), "d"(sizeof(mem)-buf.len)
            : "rcx", "r11", "memory"
        );
        if (r < 1) {
            break;
        }
        buf.len += r;
    }

    b32 r = solve(buf, heap);
    asm volatile ("syscall" : : "a"(60), "D"(!r));
    __builtin_unreachable();
}
#endif
