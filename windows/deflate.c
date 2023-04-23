// DEFLATE-decompress standard input to standard output (Windows)
//   $ cc -nostartfiles -o deflate deflate.c
//   $ cl deflate.c
// Uses a zlib incidentally exposed by PresentationNative_v0300.dll.
// Ref: https://modexp.wordpress.com/2019/12/08/shellcode-compression/

#if _MSC_VER
  #pragma comment(linker, "/subsystem:console")
  #pragma comment(lib, "kernel32.lib")
  #define ENTRYPOINT
#elif __GNUC__
  typedef __SIZE_TYPE__ size_t;
  #if __i686__
    #define ENTRYPOINT __attribute__((force_align_arg_pointer))
  #else
    #define ENTRYPOINT
  #endif
#endif

__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(int);
__declspec(dllimport) void *__stdcall GetProcAddress(void *, char *);
__declspec(dllimport) void *__stdcall GetStdHandle(int);
__declspec(dllimport) void *__stdcall LoadLibraryA(char *);
__declspec(dllimport) int __stdcall ReadFile(void*, void*, int, int*, void*);
__declspec(dllimport) void *__stdcall VirtualAlloc(void*, size_t, int, int);
__declspec(dllimport) int __stdcall WriteFile(void*, void*, int, int*, void*);

#define Z_FINISH      4
#define Z_OK          0
#define Z_STREAM_END  1
#define Z_BUF_ERROR  -5

#define NEW(arena, type) (type *)alloc(arena, 1, sizeof(type))
#define ARRAY(arena, type, count) (type *)alloc(arena, count, sizeof(type))
#define DIE(msg) die(msg, sizeof(msg)-1)

__declspec(noreturn) static void die(char *msg, int len)
{
    void *stderr = GetStdHandle(-12);
    WriteFile(stderr, msg, len, &len, 0);
    ExitProcess(1);
}

typedef struct {
    int cap;
    int off;
} Arena;

static Arena *newarena(int size)
{
    Arena *arena = (Arena *)VirtualAlloc(0, size, 0x3000, 4);
    if (arena) {
        arena->cap = size;
        arena->off = sizeof(*arena);
    }
    return arena;
}

ENTRYPOINT
static void *__stdcall alloc(Arena *arena, unsigned count, unsigned size)
{
    char *p = 0;
    if (arena && count<0x7fffffff/size) {
        int total = count * size;
        int align = -total & 7;
        int avail = arena->cap - arena->off;
        if (total < avail-align) {
            p = (char *)arena + arena->off;
            arena->off += total + align;
        }
    }
    return (void *)p;
}

ENTRYPOINT
static void __stdcall nopfree(Arena *arena, void *p)
{
    (void)arena;
    (void)p;
}

typedef struct {
    char *next_in;
    int   avail_in;
    int   total_in;
    char *next_out;
    int   avail_out;
    int   total_out;
    char *msg;
    void *internal;
    void *(__stdcall *alloc)(Arena *, unsigned, unsigned);
    void (__stdcall *free)(Arena *, void *);
    Arena *arena;
    int   reserved[3];
} Stream;

typedef int __stdcall InitProc(Stream *, char *, int);
typedef int __stdcall InflateProc(Stream *, int);
typedef struct {
    void        *mod;
    InitProc    *init;
    InflateProc *inflate;
} Zlib;

static Zlib *loadzlib(Arena *arena)
{
    Zlib *lib = NEW(arena, Zlib);
    if (lib) {
        lib->mod = LoadLibraryA("PresentationNative_v0300");
        lib->init = (InitProc *)GetProcAddress(lib->mod, "ums_inflate_init");
        lib->inflate = (InflateProc *)GetProcAddress(lib->mod, "ums_inflate");
        if (!lib->mod || !lib->init || !lib->inflate) {
            return 0;
        }
    }
    return lib;
}

static void flush(void *stdout, Stream *z, char *bufout)
{
    int len = (int)(z->next_out - bufout);
    if (len && !WriteFile(stdout, bufout, len, &len, 0)) {
        DIE("deflate: write to standard output failed\n");
    }
}

__declspec(noreturn) static void invalid(void)
{
    DIE("deflate: input is not a valid DEFLATE stream\n");
}

ENTRYPOINT
void mainCRTStartup(void)
{
    Arena *arena = newarena(1<<20);
    int bufsize  = 1<<16;
    char *bufin  = ARRAY(arena, char, bufsize);
    char *bufout = ARRAY(arena, char, bufsize);
    void *stdin  = GetStdHandle(-10);
    void *stdout = GetStdHandle(-11);

    Stream *z  = NEW(arena, Stream);
    z->alloc   = alloc;
    z->free    = nopfree;
    z->arena   = arena;
    Zlib *zlib = loadzlib(arena);
    if (!zlib) {
        DIE("deflate: could not find zlib\n");
    }
    if (zlib->init(z, "1", sizeof(*z))) {
        DIE("deflate: zlib initialization failed\n");
    }

    for (;;) {
        z->next_in = bufin;
        ReadFile(stdin, bufin, sizeof(bufin), &z->avail_in, 0);
        if (!z->avail_in) {
            break;
        }
        do {
            z->next_out = bufout;
            z->avail_out = sizeof(bufout);
            switch (zlib->inflate(z, 0)) {
            default:           invalid();
            case Z_STREAM_END: flush(stdout, z, bufout);
                               ExitProcess(0);
            case Z_OK:         flush(stdout, z, bufout);
            }
        } while (z->avail_in);
    }

    for (;;) {
        z->next_out = bufout;
        z->avail_out = sizeof(bufout);
        switch (zlib->inflate(z, Z_FINISH)) {
        default:           invalid();
        case Z_STREAM_END: flush(stdout, z, bufout);
                           ExitProcess(0);
        case Z_BUF_ERROR:  if (z->avail_out) invalid();
                           flush(stdout, z, bufout);
        }
    }
}
