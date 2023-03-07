// getip - determine and print public IP address to standard output
//
// Mingw-w64:
//    $ cc -Os -fno-asynchronous-unwind-tables -s -nostartfiles
//         -Wl,--gc-sections -o getip.exe getip.c -lwininet
// MSVC:
//    C:\>cl /O2 /GS- getip.c
//
// This is free and unencumbered software released into the public domain.
#include <windows.h>
#include <wininet.h>
#if defined(_MSC_VER)
#    pragma comment(lib, "kernel32")
#    pragma comment(lib, "wininet")
#    pragma comment(linker, "/subsystem:console")
#endif

// This host echos its "X-Forwarded-For" header, which is populated by its
// own load balancer. The contents are partially encoded with HTML entity
// probably to avoid XSS issues since it contains untrusted inputs.
#define URL "https://www.ups.com/mnm/getBrowserIp"

// Decode numeric, ASCII HTML entities in place. Returns the decoded length.
// Invalid entities, non-ASCII entities, and control bytes are all decoded
// to space. Stops at the first comma.
static int decode(unsigned char *buf, int len)
{
    int n = 0, s = 0, e = 0;
    for (int i = 0; i < len; i++) {
        switch (s) {
        case 0: switch (buf[i]) {
                case '&': s = 1; break;
                case ',': return n;
                default : buf[n++] = buf[i];
                } break;
        case 1: switch (buf[i]) {
                case '#': s = 2; break;
                default : e = 127; s = 2;
                } break;
        case 2: switch (buf[i]) {
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                          e = e*10 + buf[i] - '0';
                          e = e>=127 ? 127 : e;  // no overflow
                          break;
                case ';': if (e == ',') return n;
                          buf[n++] = e<32 || e>=127 ? ' ' : (unsigned char)e;
                          e = s = 0;
                          break;
                default : e = 127;
                } break;
        }
    }
    return n;
}

#define SUCCESS (Err){0, 0}
#define ERR(s) (Err){(unsigned char *)s, sizeof(s)-1}
typedef struct {
    unsigned char *err;
    int len;
} Err;

// Returns an error message, or null on success.
static Err run(void)
{
    HINTERNET h = InternetOpenA("wininet", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
    if (!h) return ERR("InternetOpenA()");

    HINTERNET r = InternetOpenUrlA(h, URL, 0, 0, 0, 0);
    if (!r) return ERR("InternetOpenUrlA()");

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n;
    unsigned char buf[256];
    if (!InternetReadFile(r, buf, sizeof(buf)-1, &n)) {
        return ERR("InternetReadFile()");
    }

    n = decode(buf, n);
    buf[n++] = '\n';
    if (!WriteFile(out, buf, n, &n, 0)) {
        return ERR("WriteFile()");
    }

    InternetCloseHandle(r);
    InternetCloseHandle(h);
    return SUCCESS;
}

typedef struct {
    int off;
    unsigned char buf[128];
} Buf;

static void append(Buf *b, void *src, int len)
{
    unsigned char *s = src;
    int avail = sizeof(b->buf) - b->off;
    int count = len<avail ? len : avail;
    for (int i = 0; i < count; i++) {
        b->buf[b->off++] = s[i];
    }
}

#if __i686__
__attribute__((force_align_arg_pointer))
#endif
void mainCRTStartup(void)
{
    int ret = 0;
    Err err = run();
    if (err.err) {
        HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
        Buf buf = {0};
        append(&buf, "getip: ", 7);
        append(&buf, err.err, err.len);
        append(&buf, " failure\n", 9);
        DWORD n;
        WriteFile(h, buf.buf, buf.off, &n, 0);
        ret = 1;
    }
    ExitProcess(ret);
}
