// Lexicographic sort from standard input to standard output
// w64devkit:  $ cc -nostartfiles -O3 -o sort.exe sort.c
// msvc/clang: $ cl /O2 sort.c /link /subsystem:console kernel32.lib
// linux:      $ cc -O3 -o sort sort.c
// This is free and unencumbered software released into the public domain.

// Platform Interface

typedef int Bool;
typedef long long Size;  // 64-bit only
typedef unsigned char Byte;

typedef struct {
    Byte *data;
    Size len;
} Buffer;

static void *alloc(Size, Size);
static Bool fullwrite(Byte *, int);
static Bool sortmain(Buffer);


// Application Implementation

static Size countlines(Buffer b)
{
    Size count = 0;
    for (Size i = 0; i < b.len; i++) {
        count += b.data[i] == '\n';
    }
    count += b.len ? b.data[b.len-1]!='\n' : 0;
    return count;
}

static void getlines(Buffer b, Buffer *restrict lines)
{
    Size n = 0;
    for (Size i = 0; i < b.len; i++) {
        Byte c = b.data[i];
        lines[n].data = lines[n].len ? lines[n].data : b.data+i;
        lines[n].len += c!='\n';
        n += c=='\n';
    }
}

static Size compare(Buffer a, Buffer b)
{
    Size len = a.len<b.len ? a.len : b.len;
    for (Size i = 0; i < len; i++) {
        int c = a.data[i] - b.data[i];
        if (c) {
            return c;
        }
    }
    return a.len - b.len;
}

static void splitmerge(Buffer *dst, Size beg, Size end, Buffer *src)
{
    if (end - beg <= 1) {
        return;
    }
    Size mid = (end + beg) / 2;
    splitmerge(src, beg, mid, dst);
    splitmerge(src, mid, end, dst);

    Size i = beg;
    Size j = mid;
    for (Size k = beg; k < end; k++) {
        if (i<mid && (j>=end || compare(src[i], src[j])<=0)) {
            dst[k] = src[i++];
        } else {
            dst[k] = src[j++];
        }
    }
}

typedef struct {
    Size count;
    Buffer *lines;
    Bool status;
} Lines;

static Lines sort(Buffer b)
{
    Lines result = {0};
    Size count = countlines(b);
    Buffer *lines = alloc(sizeof(*lines), 2*count);
    if (!lines) {
        return result;
    }
    Buffer *scratch = lines + count;

    getlines(b, lines);
    for (Size i = 0; i < count; i++) {
        scratch[i] = lines[i];
    }
    splitmerge(lines, 0, count, scratch);

    result.count = count;
    result.lines = lines;
    result.status = 1;
    return result;
}

typedef struct {
    Byte buf[1<<16];
    int len;
    Bool err;
} Output;

static void flush(Output *o)
{
    if (!o->err && o->len) {
        o->err |= !fullwrite(o->buf, o->len);
        o->len = 0;
    }
}

static void append(Output *o, Byte *buf, Size len)
{
    Byte *end = buf + len;
    while (!o->err && buf<end) {
        int avail = (int)sizeof(o->buf) - o->len;
        int count = avail<end-buf ? avail : (int)(end-buf);
        Byte *dst = o->buf + o->len;
        for (int i = 0; i < count; i++) {
            dst[i] = buf[i];
        }
        o->len += count;
        buf += count;
        if (o->len == (int)sizeof(o->buf)) {
            flush(o);
        }
    }
}

static void newline(Output *o)
{
    Byte n = '\n';
    append(o, &n, 1);
}

static Bool sortmain(Buffer input)
{
    Lines lines = sort(input);
    Output *o = alloc(sizeof(*o), 1);
    for (Size i = 0; i < lines.count; i++) {
        append(o, lines.lines[i].data, lines.lines[i].len);
        newline(o);
    }
    flush(o);
    return !lines.status || o->err;
}


// Platform Implementation

#if __AFL_COMPILER
// $ afl-clang-fast -g3 -fsanitize=address,undefined sort.c
// $ mkdir i
// $ seq 100 | shuf >i/100
// $ afl-fuzz -m32T -ii -oo ./a.out
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

static void *alloc(Size size, Size len)
{
    assert(size > 0);
    assert(len >= 0);
    return calloc(size, len);
}

static Bool fullwrite(Byte *buf, int len)
{
    assert(buf);
    assert(len > 0);
    return 1;
}

int main(void)
{
    #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    #endif

    Buffer input = {0};
    Byte *fuzzin = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        input.len = __AFL_FUZZ_TESTCASE_LEN;
        input.data = realloc(input.data, input.len);
        memcpy(input.data, fuzzin, input.len);
        sortmain(input);
    }
    return 0;
}

#elif _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void *alloc(ptrdiff_t size, ptrdiff_t count)
{
    return VirtualAlloc(
        0, size*count, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE
    );
}

static Bool fullwrite(Byte *buf, int len)
{
    HANDLE stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dummy;
    return WriteFile(stdout, buf, len, &dummy, 0);
}

static Bool mapstdin(Buffer *b)
{
    HANDLE stdin = GetStdHandle(STD_INPUT_HANDLE);

    LARGE_INTEGER size;
    if (!GetFileSizeEx(stdin, &size)) {
        return 0;
    }

    HANDLE map = CreateFileMappingA(
        stdin, 0, PAGE_READONLY, size.HighPart, size.LowPart, 0
    );
    if (!map) {
        return 0;
    }

    b->data = MapViewOfFile(
        map, FILE_MAP_READ, 0, size.HighPart, size.LowPart
    );
    CloseHandle(map);
    b->len = size.QuadPart;
    return b->data ? 1 : 0;
}

static Bool readstdin(Buffer *b)
{
    HANDLE stdin = GetStdHandle(STD_INPUT_HANDLE);

    b->len = 0;
    b->data = VirtualAlloc(0, (size_t)1<<40, MEM_RESERVE, PAGE_READWRITE);
    if (!b->data) {
        return 0;
    }

    size_t cap = 0;
    for (;;) {
        size_t avail = cap - b->len;
        if (!avail) {
            cap = cap ? cap<<1 : 1<<21;
            if (!VirtualAlloc(b->data, cap, MEM_COMMIT, PAGE_READWRITE)) {
                return 0;
            }
            avail = cap - b->len;
        }

        DWORD len = avail>0xffffffff ? 0xffffffff : (DWORD)avail;
        ReadFile(stdin, b->data+b->len, len, &len, 0);
        if (!len) {
            return 1;
        }
        b->len += len;
    }
}

int mainCRTStartup(void)
{
    Buffer buf;
    if (!mapstdin(&buf) && !readstdin(&buf)) {
        return 1;
    }
    return sortmain(buf);
}


#elif __linux
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void *alloc(Size size, Size count)
{
    void *p = mmap(
        0, size*count, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0
    );
    return p==MAP_FAILED ? 0 : p;
}

static Bool fullwrite(Byte *buf, int len)
{
    for (int off = 0; off < len;) {
        int r = (int)write(1, buf+off, len-off);
        if (r < 0) {
            return 0;
        }
        off += r;
    }
    return 1;
}

static Bool mapstdin(Buffer *b)
{
    struct stat st;
    if (fstat(0, &st)) {
        return 0;
    }
    b->data = mmap(0, st.st_size, PROT_READ, MAP_SHARED, 0, 0);
    b->len = st.st_size;
    return b->data==MAP_FAILED ? 0 : 1;
}

static Bool readstdin(Buffer *b)
{
    b->len = 0;
    b->data = mmap(
        0, (size_t)1<<40, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0
    );
    if (b->data == MAP_FAILED) {
        return 0;
    }

    size_t cap = 0;
    for (;;) {
        size_t avail = cap - b->len;
        if (!avail) {
            cap = cap ? cap<<1 : 1<<21;
            if (mprotect(b->data, cap, PROT_READ|PROT_WRITE)) {
                return 0;
            }
            avail = cap - b->len;
        }
        ssize_t r = read(0, b->data+b->len, avail);
        switch (r) {
        case -1: return 0;
        case  0: return 1;
        }
        b->len += r;
    }
}

int main(void)
{
    Buffer buf;
    if (!mapstdin(&buf) && !readstdin(&buf)) {
        return 1;
    }
    return sortmain(buf);
}
#endif
