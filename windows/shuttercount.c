// Nikon Shutter Count Reader
// $ echo '1 ICON "shuttercount.ico"' | windres -o shuttercount.o
// $ cc -nostartfiles -mwindows -O -s -o shuttercount.exe shuttercount.[co]
// MSVC:
// $ cl /O1 shuttercount.c /link /subsystem:windows
//       kernel32.lib shell32.lib user32.lib libvcruntime.lib
//
// Drag-and-drop a JPEG or NEF over the EXE to display the Nikon Shutter
// Count Exif field. It does not actually parse JPEF, NEF, nor Exif, but
// operates on a simple heuristic with high reliability in practice.
//
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <string.h>

#define new(a, t, n)  (t *)alloc(a, sizeof(t)*n)

typedef unsigned char      u8;
typedef unsigned short     char16_t;
typedef          char16_t  c16;
typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef          ptrdiff_t size;
typedef          size_t    uptr;
typedef          char      byte;

static i32 osread(i32 fd, u8 *, i32);

typedef struct {
    byte *beg;
    byte *end;
} arena;

static byte *alloc(arena *a, size len)
{
    if (len > a->end - a->beg) {
        *(volatile int *)0 = 0;
    }
    return memset(a->end -= len, 0, len);
}

typedef struct {
    u8 *buf;
    i32 cap;
    i32 len;
    i32 off;
    i32 fd;
} i32reader;

static i32reader *newu8buf(i32 fd, arena *perm)
{
    i32reader *b = new(perm, i32reader, 1);
    b->cap = 1<<16;
    b->buf = new(perm, u8, b->cap);
    b->fd  = fd;
    return b;
}

typedef struct {
    i32 value;
    b32 ok;
} i32result;

static i32result i32read(i32reader *b)
{
    i32result r = {0};

    while (b->len-b->off < 4) {
        if (b->off) {
            memmove(b->buf, b->buf+b->off, b->len-b->off);
            b->len -= b->off;
            b->off  = 0;
        }
        i32 count = osread(b->fd, b->buf+b->len, b->cap-b->len);
        if (count < 1) {
            return r;
        }
        b->len += count;
    }

    u8 *p = b->buf + b->off;
    b->off += 4;
    r.value = (u32)p[0] | (u32)p[1]<<8 | (u32)p[2]<<16 | (u32)p[3]<<24;
    r.ok = 1;
    return r;
}

// Returns non-negative shutter count, or a negative next state.
static i32 parse(i32 state, i32 v)
{
    // a7:00  04:00  01:00:00:00  xx:xx:xx:xx
    // [tag] [type]  [nmemb    ]  [counter  ]  (little endian)
    switch (state) {
    case -2: if (v == 0x00000001) return -3;
             break;
    case -3: if (v >= 0 && v < 10000000) return v;
    }
    return -1 - (v == 0x000400a7);
}

static c16 *encode(c16 *p, i32 x)
{
    *--p = 0;
    i32 len = 0;
    do {
        *--p = (u8)(x%10) + '0';
        if (++len%3==0 && x>9) {
            *--p = ',';
        }
    } while (x /= 10);
    return p;
}

static c16 *prepend(c16 *p, u8 *s)
{
    size i = 0;
    for (; s[i]; i++) {}
    while (i) *--p = s[--i];
    return p;
}

static c16 *shuttercount(i32 fd, void *mem, i32 cap)
{
    arena scratch = {0};
    scratch.beg = mem;
    scratch.end = scratch.beg + cap;

    i32reader *b = newu8buf(fd, &scratch);
    for (i32 state = 0;;) {
        i32result next = i32read(b);
        if (!next.ok) {
            return 0;
        }
        state = parse(state, next.value);
        if (state >= 0) {
            c16 *r = new(&scratch, c16, 64);
            r = encode(r, state);
            r = prepend(r, (u8 *)"Shutter Count: ");
            return r;
        }
    }
}

// Platform-specific

#define W32(r) __declspec(dllimport) r __stdcall
W32(b32)    CloseHandle(uptr);
W32(c16 **) CommandLineToArgvW(c16 *, i32 *);
W32(i32)    CreateFileW(c16 *, i32, i32, uptr, i32, i32, uptr);
W32(void)   ExitProcess(i32);
W32(c16 *)  GetCommandLineW(void);
W32(b32)    MessageBoxW(uptr, c16 *, c16 *, i32);
W32(b32)    ReadFile(uptr, u8 *, i32, i32 *, uptr);
W32(void *) VirtualAlloc(uptr, size, i32, i32);

static i32 osread(i32 fd, u8 *buf, i32 len)
{
    ReadFile(fd, buf, len, &len, 0);
    return len;
}

void WinMainCRTStartup(void)
{
    i32 cap = 1<<20;
    u8 *buf = VirtualAlloc(0, cap, 0x3000, 4);

    c16  *cmd = GetCommandLineW();
    i32   argc;
    c16 **argv = CommandLineToArgvW(cmd, &argc);

    i32 err = 0;
    for (i32 i = 1; i < argc; i++) {
        i32 h = CreateFileW(argv[i], 0x80000000, 7, 0, 3, 128, 0);
        err |= h==-1;
        c16 *r = shuttercount(h, buf, cap);
        c16 *msg = r ? r : u"Could not determine value!";
        MessageBoxW(0, msg, argv[i], 0);
        err |= !r;
        CloseHandle(h);
    }

    ExitProcess(err);
}
