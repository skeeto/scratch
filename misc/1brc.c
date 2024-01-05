// The One Billion Row Challenge
// Ref: https://www.morling.dev/blog/one-billion-row-challenge/
// Ref: https://nullprogram.com/blog/2022/08/08/
//
// 1 billion rows run time (12th gen i9): ~3s at -O2, ~6s at -O0. This
// is without any optimization work, just non-pessimiation.
//
// Assumes UTF-8 lexicographic collation and naive rounding, as the
// contest does not specify either. This seems to match the natural Java
// implementation, as the results match Java entries bit-for-bit.
//
// No validation, so it's garbage-in/garbage-out, though no undefined
// behavior even for invalid input.
//
// Porting note: Call tabulate() in parallel with one a thread per core,
// with input chunked on line boundaries, one table per thread. Then
// call finalize() with all tables and a ~2MiB arena, then write out the
// result.
//
// This is free and unencumbered software released into the public domain.

#define TABLE_EXPONENT 12  // support up to 2**12-1 (4,095) cities

#define assert(c)     while (!(c)) __builtin_unreachable()
#define countof(a)    (size)(sizeof(a) / sizeof(*(a)))
#define max(a, b)     ((a)>(b) ? (a) : (b))
#define min(a, b)     ((a)<(b) ? (a) : (b))
#define new(a, t, n)  (t *)alloc(a, sizeof(t)*n)
#define s8(s)         (s8){(u8 *)s, countof(s)-1}

typedef unsigned char      u8;
typedef   signed short     i16;
typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef   signed long long i64;
typedef unsigned long long u64;
typedef   signed long long size;
typedef unsigned long long uptr;
typedef          char      byte;

typedef struct {
    byte *beg;
    byte *end;
} arena;

static byte *alloc(arena *a, size len)
{
    if (len > a->end - a->beg) {
        assert(!"out of memory");
    }
    return a->end -= len;
}

typedef struct {
    u8  *data;
    size len;
} s8;

static s8 s8span(u8 *beg, u8 *end)
{
    s8 s = {0};
    s.data = beg;
    s.len = end - beg;
    return s;
}

static u64 s8hash(s8 s)
{
    u64 h = 0;
    __builtin_memcpy(&h, s.data, min(8, s.len));
    return h * 1111111111111111111u;
}

static b32 s8equal(s8 a, s8 b)
{
    return a.len==b.len && !__builtin_memcmp(a.data, b.data, a.len);
}

static size s8compare(s8 a, s8 b)
{
    size len = a.len<b.len ? a.len : b.len;
    size r = len ? __builtin_memcmp(a.data, b.data, len) : b.len-a.len;
    return r ? r : a.len-b.len;
}

typedef struct {
    s8 head;
    s8 tail;
} cut;

// Cut the string into two strings at position i.
static cut s8cut(s8 s, size i)
{
    assert(i >= 0);
    assert(i <= s.len);
    cut r = {0};
    r.head.data = s.data;
    r.head.len = i;
    r.tail.data = s.data + i;
    r.tail.len = s.len - i;
    return r;
}

typedef struct {
    struct {
        s8  name;
        i16 min;
        i16 max;
        i32 sum;
        i32 count;
    } slots[1<<TABLE_EXPONENT];
    i32 len;
} table;

// Find/create an entry for the given city.
static i32 lookup(table *t, s8 name)
{
    assert(name.len > 0);
    u64 hash = s8hash(name);
    i32 mask = (1<<TABLE_EXPONENT) - 1;
    u32 step = (i32)(hash>>(64 - TABLE_EXPONENT)) | 1;
    for (i32 i = (i32)hash;;) {
        i = (i + step) & mask;
        if (!t->slots[i].name.len) {
            t->slots[i].name = name;
            t->slots[i].min  = (i16)0x7fff;
            t->slots[i].max  = (i16)0x8000;
            t->len++;
            return i;
        } else if (s8equal(t->slots[i].name, name)) {
            return i;
        }
    }
}

static void splitmerge(i32 *dst, size beg, size end, i32 *src, table *t)
{
    if (end-beg < 2) {
        return;
    }
    size mid = beg + (end - beg)/2;
    splitmerge(src, beg, mid, dst, t);
    splitmerge(src, mid, end, dst, t);

    size i = beg;
    size j = mid;
    for (size k = beg; k < end; k++) {
        s8 namei = t->slots[src[i]].name;
        s8 namej = t->slots[src[j]].name;
        if (i<mid && (j==end || s8compare(namei, namej)<1)) {
            dst[k] = src[i++];
        } else {
            dst[k] = src[j++];
        }
    }
}

// Return a sorted index of the table elements, empty slots to the end.
static i32 *sort(table *t, arena *perm)
{
    i32 *index = new(perm, i32, countof(t->slots));
    for (i32 i = 0; i < countof(t->slots); i++) {
        index[i] = i;
    }
    arena scratch = *perm;
    i32 *temp = new(&scratch, i32, countof(t->slots));
    splitmerge(index, 0, countof(t->slots), temp, t);
    return index;
}

static u8 *writes8(u8 *p, s8 s)
{
    __builtin_memcpy(p, s.data, s.len);
    return p + s.len;
}

static u8 *writei32(u8 *p, i32 x)
{
    u8 buf[16];
    u8 *beg = buf + countof(buf);
    i32 t = x<0 ? x : -x;
    *--beg = '0' - (u8)(t%10);
    *--beg = '.';
    t /= 10;
    do {
        *--beg = '0' - (u8)(t%10);
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    return writes8(p, s8span(beg, buf+countof(buf)));
}

// Format the table in the given order into the buffer, returning the end.
static u8 *format(u8 *p, table *t, i32 *index)
{
    p = writes8(p, s8("{"));
    for (i32 n = 0;; n++) {
        i32 i = index[n];
        if (!t->slots[i].name.len) {
            return writes8(p, s8("}\n"));
        }
        if (n > 0) {
            p = writes8(p, s8(", "));
        }
        p = writes8(p, t->slots[i].name);
        p = writes8(p, s8("="));
        p = writei32(p, t->slots[i].min);
        p = writes8(p, s8("/"));
        double mean = (double)t->slots[i].sum/t->slots[i].count;
        mean += mean<0 ? -0.5 : +0.5;  // rounding
        p = writei32(p, (i32)mean);
        p = writes8(p, s8("/"));
        p = writei32(p, t->slots[i].max);
    }
}

// Merge the second table into the first.
static void merge(table *dst, table *src)
{
    for (i32 s = 0; s < countof(src->slots); s++) {
        s8 sname = src->slots[s].name;
        if (!sname.len) continue;
        i32 d = lookup(dst, sname);
        dst->slots[d].min = min(dst->slots[d].min, src->slots[s].min);
        dst->slots[d].max = max(dst->slots[d].max, src->slots[s].max);
        dst->slots[d].sum += src->slots[s].sum;
        dst->slots[d].count += src->slots[s].count;
    }
}

// Tabulate the information from input into the table. The table must be
// zero-initialized on first use.
static void tabulate(s8 input, table *t)
{
    u8 *beg = input.data;
    u8 *end = input.data + input.len;
    while (beg < end) {
        s8 name = {0};
        name.data = beg;
        for (; name.data[name.len] != ';'; name.len++) {}
        u8 *p = name.data + name.len + 1;

        i32 sign = *p=='-' ? -1 : +1;
        p += *p=='-';

        i32 len = 0;
        u8 digits[4];
        digits[len++] = '0';
        do {
            digits[len] = *p;
            len += *p >= '0';
        } while (p+1<end && *++p!='\n' && len<countof(digits));
        beg = p + 1;

        assert(len>=3 && len<=4);
        i32 temp = ((i32)digits[len-3] - '0')*100 +
                   ((i32)digits[len-2] - '0')*10 +
                   ((i32)digits[len-1] - '0')*1;
        temp *= sign;

        i32 i = lookup(t, name);
        t->slots[i].min = min(t->slots[i].min, (i16)temp);
        t->slots[i].max = max(t->slots[i].max, (i16)temp);
        t->slots[i].sum += temp;
        t->slots[i].count++;
    }
}

// Merge the tables and produce a sorted report.
static s8 finalize(table *ts, i32 len, arena *perm)
{
    for (i32 i = 1; i < len; i++) {
        merge(ts+0, ts+i);
    }
    i32 *index = sort(ts+0, perm);
    u8 *beg = new(perm, u8, 1<<18);
    u8 *end = format(beg, ts+0, index);
    return s8span(beg, end);
}


#if _WIN32
// $ gcc -O2 -nostartfiles -o 1brc 1brc.c
// $ clang-cl /O2 1brc.c /link /subsystem:console kernel32.lib libvcruntime.lib
// $ ./1brc <measurements2.txt
// NOTE: Assumes unix newlines despite the platform.

#define W32(r) __declspec(dllimport) r __stdcall
W32(uptr)   CreateFileMappingA(uptr, uptr, i32, i32, i32, uptr);
W32(uptr)   CreateThread(uptr, size, void *, void *, i32, i32 *);
W32(void)   ExitProcess(i32);
W32(b32)    GetFileSizeEx(uptr, i64 *);
W32(uptr)   GetStdHandle(i32);
W32(void)   GetSystemInfo(i32 *);
W32(void *) MapViewOfFile(uptr, i32, i32, i32, size);
W32(void *) VirtualAlloc(uptr, size, i32, i32);
W32(i32)    WaitForSingleObject(uptr, i32);
W32(b32)    WriteFile(uptr, u8 *, i32, i32 *, uptr);

enum {
    FILE_MAP_READ = 4,

    MEM_COMMIT  = 0x1000,
    MEM_RESERVE = 0x2000,

    PAGE_READONLY  = 2,
    PAGE_READWRITE = 4,

    STD_INPUT_HANDLE  = -10,
    STD_OUTPUT_HANDLE = -11,
};

static arena newarena(size cap)
{
    arena a = {0};
    a.beg = VirtualAlloc(0, cap, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    a.end = a.beg + cap;
    return a;
}

typedef struct {
    s8     input;
    table *result;
} job;

static i32 __stdcall worker(job *j)
{
    tabulate(j->input, j->result);
    return 0;
}

static i32 proccount(void)
{
    i32 data[12];
    GetSystemInfo(data);
    return data[8];  // dwNumberOfProcessors (x64)
}

void mainCRTStartup(void)
{
    b32 err = 0;

    s8 input = {0};
    uptr stdin = GetStdHandle(STD_INPUT_HANDLE);
    err |= !GetFileSizeEx(stdin, &input.len);
    uptr h = CreateFileMappingA(
        stdin, 0, PAGE_READONLY, (i32)(input.len>>32), (i32)input.len, 0
    );
    input.data = MapViewOfFile(h, FILE_MAP_READ, 0, 0, input.len);

    arena perm = newarena(1<<24);

    i32 nthreads = proccount();
    size chunksize = input.len / nthreads;
    table *ts = new(&perm, table, nthreads);  // NOTE: assumes zeroed arena
    job *jobs = new(&perm, job, nthreads);
    uptr *handles = new(&perm, uptr, nthreads);
    for (i32 i = 0; i < nthreads; i++) {
        jobs[i].result = ts + i;
        if (i < nthreads-1) {
            // TODO: move chunking routine into platform-agnostic code
            size split = chunksize;
            for (; split && input.data[split-1] != '\n'; split--) {}
            cut cuts = s8cut(input, split);
            jobs[i].input = cuts.head;
            input = cuts.tail;
            // NOTE: No thread uses even ~1KiB of stack; 4KiB is plenty.
            // TODO: check CreateThread error
            handles[i] = CreateThread(0, 1<<12, worker, jobs+i, 0, 0);
        } else {
            jobs[i].input = input;
            worker(jobs+i);
        }
    }

    for (i32 i = 0; i < nthreads-1; i++) {
        WaitForSingleObject(handles[i], -1);
    }

    s8 output = finalize(ts, nthreads, &perm);

    uptr stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    i32 dummy;
    err |= !WriteFile(stdout, output.data, (i32)output.len, &dummy, 0);
    ExitProcess(err);
}
#endif
