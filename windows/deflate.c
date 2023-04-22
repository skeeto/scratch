// DEFLATE-decompress standard input to standard output (Windows)
//   $ cc -nostartfiles -o deflate deflate.c
//   $ cl deflate.c
// Uses a zlib incidentally exposed by PresentationNative_v0300.dll.
// Ref: https://modexp.wordpress.com/2019/12/08/shellcode-compression/

#define BUFSIZE       (1<<16)
#define Z_FINISH      4
#define Z_OK          0
#define Z_STREAM_END  1
#define Z_BUF_ERROR  -5

#ifdef _MSC_VER
  #pragma comment(linker, "/subsystem:console")
  #pragma comment(lib, "kernel32.lib")
  void *memset(void *, int, size_t);
  #pragma function(memset)
  void *memset(void *dst, int c, size_t len)
  {
      char *d = (char *)dst;
      for (; len; len--) *d++ = (char)c;
      return dst;
  }
#endif

__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(int);
__declspec(dllimport) void *__stdcall GetProcAddress(void *, char *);
__declspec(dllimport) void *__stdcall GetStdHandle(int);
__declspec(dllimport) void *__stdcall LoadLibraryA(char *);
__declspec(dllimport) int __stdcall ReadFile(void*, void*, int, int*, void*);
__declspec(dllimport) int __stdcall WriteFile(void*, void*, int, int*, void*);

#define DIE(s) die(s, sizeof(s)-1)
__declspec(noreturn) static void die(char *msg, int len)
{
    void *stderr = GetStdHandle(-12);
    WriteFile(stderr, msg, len, &len, 0);
    ExitProcess(1);
}

typedef struct {
    char *next_in;
    int   avail_in;
    int   total_in;
    char *next_out;
    int   avail_out;
    int   total_out;
    void *reserved1[5];
    int   reserved2[3];
} Stream;

typedef int __stdcall InitProc(Stream *, char *, int);
typedef int __stdcall InflateProc(Stream *, int);
typedef struct {
    InitProc    *init;
    InflateProc *inflate;
} Zlib;

static Zlib loadzlib(void)
{
    Zlib zlib = {0};
    void *module = LoadLibraryA("PresentationNative_v0300");
    zlib.init = (InitProc *)GetProcAddress(module, "ums_inflate_init");
    zlib.inflate = (InflateProc *)GetProcAddress(module, "ums_inflate");
    if (!module || !zlib.init || !zlib.inflate) {
        DIE("deflate: zlib load failed\n");
    }
    return zlib;
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

#if __i686__
__attribute__((force_align_arg_pointer))
#endif
void mainCRTStartup(void)
{
    static char bufin[BUFSIZE];
    static char bufout[BUFSIZE];
    void *stdin  = GetStdHandle(-10);
    void *stdout = GetStdHandle(-11);

    Stream z = {0};
    Zlib zlib = loadzlib();
    if (zlib.init(&z, "1", sizeof(z))) {
        DIE("deflate: zlib initialization failed\n");
    }

    for (;;) {
        z.next_in = bufin;
        ReadFile(stdin, bufin, sizeof(bufin), &z.avail_in, 0);
        if (!z.avail_in) {
            break;
        }
        do {
            z.next_out = bufout;
            z.avail_out = sizeof(bufout);
            switch (zlib.inflate(&z, 0)) {
            default:
                invalid();
            case Z_STREAM_END:
                flush(stdout, &z, bufout);
                ExitProcess(0);
            case Z_OK:
                flush(stdout, &z, bufout);
                break;
            }
        } while (z.avail_in);
    }

    for (;;) {
        z.next_out = bufout;
        z.avail_out = sizeof(bufout);
        switch (zlib.inflate(&z, Z_FINISH)) {
        default:
            invalid();
        case Z_STREAM_END:
            flush(stdout, &z, bufout);
            ExitProcess(0);
        case Z_BUF_ERROR:
            if (z.avail_out) {
                invalid();
            }
            flush(stdout, &z, bufout);
        }
    }
}
