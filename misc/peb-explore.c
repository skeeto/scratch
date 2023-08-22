// Demonstrates some PEB traversal
// $ cc -nostartfiles -fno-builtin -o peb-explore peb-explore.c
// $ cl /GS- peb-explore.c /link /subsystem:console kernel32.lib
//
// Using only one import, WriteConsoleW, this program prints its command
// line, loaded DLLs, and HOME environment variable. It finds all the
// necessary information and handles in the PEB. Works on at least x86
// and x64 with both Mingw-w64 and MSVC. No assembly required.
//
// It's not safe to traverse the module list concurrently with DLL
// loading, and this program does not hold the undocumented lock. Such
// concurrent loads may be triggered by another process, or by a thread
// injected by another process, and so in such conditions this program
// may crash. Therefore the this technique is impractical.
//
// This is free and unencumbered software released into the public domain.

typedef unsigned char byte;
typedef   signed int  i32;
typedef unsigned int  u32;
typedef   signed int  b32;
#if _WIN64
  typedef long long size;
#else
  typedef long size;
#endif
typedef unsigned short wchar_t;  // for GDB and RemedyBG
typedef wchar_t c16;

#define W32(r) __declspec(dllimport) r __stdcall
W32(i32) WriteConsoleW(void *, c16 *, u32, u32 *, void *);

typedef struct dll dll;
struct dll {
    dll  *next;
    void *pad1[5];
    void *base;
    void *entry;
    size  size;
    void *pad2[1];
    c16  *path;
};

typedef struct {
    byte  pad1[8];
    void *pad2[1];
    dll  *next;
} ldr;

typedef struct {
    byte    pad1[16];
    void   *console;
    u32     flags;
    void   *stdin;
    void   *stdout;
    void   *stderr;
    void   *pad2[6];
    c16    *image;
    void   *pad3[1];
    c16    *cmdline;
    c16    *env;
} params;

typedef struct {
    byte    pad1[4];
    void   *pad2[2];
    ldr    *ldr;
    params *params;
} peb;

static c16 upcase(c16 c)
{
    return c>='a' && c<='z' ? (c16)(c+'A'-'a') : c;
}

static size c16len(c16 *s)
{
    size len = 0;
    for (; s[len]; len++);
    return len;
}

typedef struct {
    void *sink;
    c16  *buf;
    i32   cap;
    i32   len;
    i32   err;
} c16out;

static void flush(c16out *o)
{
    if (!o->err && o->len) {
        u32 dummy;
        o->err |= !WriteConsoleW(o->sink, o->buf, o->len, &dummy, 0);
        o->len = 0;
    }
}

static void print(c16out *o, c16 *buf, size len)
{
    c16 *end = buf + len;
    while (!o->err && buf<end) {
        i32 avail = o->cap - o->len;
        i32 count = avail<(end-buf) ? avail : (i32)(end-buf);
        c16 *dst  = o->buf + o->len;
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

static void printc16(c16out *o, c16 c)
{
    print(o, &c, 1);
}

static void prints(c16out *o, c16 *s)
{
    print(o, s, c16len(s));
}

u32 mainCRTStartup(peb *peb)
{
    c16 buf[256];
    c16out out[1] = {0};
    out->sink = peb->params->stdout;
    out->buf  = buf;
    out->cap  = sizeof(buf)/sizeof(*buf);

    prints(out, peb->params->cmdline);
    printc16(out, '\n');

    for (dll *dll = peb->ldr->next; dll->base; dll = dll->next) {
        prints(out, dll->path);
        printc16(out, '\n');
    }

    char *key = "HOME=";
    for (c16 *env = peb->params->env; *env;) {
        size len = c16len(env);
        b32 match = 1;
        for (size i = 0; i<len && key[i]; i++) {
            match &= upcase(env[i]) == key[i];
        }
        if (match) {
            print(out, env, len);
            printc16(out, '\n');
        }
        env += len + 1;
    }

    flush(out);
    return out->err;
}
