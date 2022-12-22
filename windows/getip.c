// getip - determine and print public IP address to standard output
//
// Mingw-w64:
//    $ cc -Os -ffreestanding -fno-ident -fno-asynchronous-unwind-tables \
//         -s -nostdlib -o getip.exe getip.c -lkernel32 -lwininet
// MSVC:
//    C:\>cl /Os /GS- getip.c
//
// Note: Unfortunately this program usually hangs on exit due to an old DLL
// unload deadlock defect in wininet.dll. Please fix this, Microsoft!
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
static int
decode(char *buf, int len)
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
                          e = e >= 127 ? 127 : e;  // no overflow
                          break;
                case ';': if (e == ',') return n;
                          buf[n++] = e < 32 || e >= 127 ? ' ' : e;
                          e = s = 0;
                          break;
                default : e = 127;
                } break;
        }
    }
    return n;
}

// Returns an error message, or null on success.
static const char *
run(void)
{
    HINTERNET h = InternetOpenA("wininet", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
    if (!h) return "InternetOpenA()";

    HINTERNET r = InternetOpenUrlA(h, URL, 0, 0, 0, 0);
    if (!r) return "InternetOpenUrlA()";

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n;
    char buf[256];
    if (!InternetReadFile(r, buf, sizeof(buf)-1, &n)) {
        return "InternetReadFile()";
    }

    n = decode(buf, n);
    buf[n++] = '\n';
    if (!WriteFile(out, buf, n, &n, 0)) {
        return "WriteFile()";
    }

    InternetCloseHandle(r);
    InternetCloseHandle(h);
    return 0;
}

int
mainCRTStartup(void)
{
    const char *err = run();
    if (err) {
        HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
        static const char pre[] = "getip: ";
        static const char suf[] = " failure\n";
        DWORD n;
        WriteFile(h, pre, sizeof(pre)-1, &n, 0);
        WriteFile(h, err, lstrlenA(err), &n, 0);
        WriteFile(h, suf, sizeof(suf)-1, &n, 0);
        return 1;
    }
    return 0;
}
