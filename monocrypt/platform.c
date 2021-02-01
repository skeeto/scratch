#include "platform.h"

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#include <ntsecapi.h>
#ifdef _MSC_VER
#  pragma comment(lib, "advapi32")
#endif

void
binary_stdio(void)
{
    /* Set stdin/stdout to binary mode. */
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
}

int
fillrand(void *buf, int len)
{
    return !RtlGenRandom(buf, len);
}

int
read_password(uint8_t *buf, int len, char *prompt)
{
    /* Ref: https://nullprogram.com/blog/2020/05/04/ */

    /* Resources that will be cleaned up */
    int pwlen = 0;
    DWORD orig = 0;
    WCHAR *wbuf = 0;
    SIZE_T wbuf_len = 0;
    HANDLE hi, ho = INVALID_HANDLE_VALUE;

    /* Set up input console handle */
    DWORD access = GENERIC_READ | GENERIC_WRITE;
    hi = CreateFileA("CONIN$", access, 0, 0, OPEN_EXISTING, 0, 0);
    if (!GetConsoleMode(hi, &orig)) goto done;
    DWORD mode = orig;
    mode |= ENABLE_PROCESSED_INPUT;
    mode |= ENABLE_LINE_INPUT;
    mode &= ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(hi, mode)) goto done;

    /* Set up output console handle */
    ho = CreateFileA("CONOUT$", GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (!WriteConsoleA(ho, prompt, strlen(prompt), 0, 0)) goto done;

    /* Allocate a wide character buffer the size of the output */
    wbuf_len = (len - 1 + 2) * sizeof(WCHAR);
    wbuf = HeapAlloc(GetProcessHeap(), 0, wbuf_len);
    if (!wbuf) goto done;

    /* Read and convert to UTF-8 */
    DWORD nread;
    if (!ReadConsoleW(hi, wbuf, len - 1 + 2, &nread, 0)) goto done;
    if (nread < 2) goto done;
    if (wbuf[nread-2] != '\r' || wbuf[nread-1] != '\n') {
        pwlen = -1;
        goto done;
    }
    wbuf[nread-2] = 0;  /* truncate "\r\n" */
    pwlen = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, (void *)buf, len, 0, 0);

done:
    if (wbuf) {
        SecureZeroMemory(wbuf, wbuf_len);
        HeapFree(GetProcessHeap(), 0, wbuf);
    }
    /* Exploit that operations on INVALID_HANDLE_VALUE are no-ops */
    WriteConsoleA(ho, "\n", 1, 0, 0);
    SetConsoleMode(hi, orig);
    CloseHandle(ho);
    CloseHandle(hi);
    return pwlen;
}

#else /* !_WIN32 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

void
binary_stdio(void)
{
    /* nothing to do */
}

int
fillrand(void *buf, int len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 1;
    int r = !fread(buf, len, 1, f);
    fclose(f);
    return r;
}

int
read_password(uint8_t *buf, int len, char *prompt)
{
    int r = 0;
    struct termios old, new;
    int tty = open("/dev/tty", O_RDWR);
    if (tty) {
        tcgetattr(tty, &old);
        write(tty, prompt, strlen(prompt));
        new = old;
        new.c_lflag &= ~ECHO;
        tcsetattr(tty, TCSANOW, &new);
        r = read(tty, buf, len);
        if (r < 0) {
            r = 0;
        } else if (r > 0 && buf[r-1] != '\n') {
            /* consume the rest of the line */
            do {
                r = read(tty, buf, len);
            } while (r > 0 && buf[r-1] != '\n');
            memset(buf, 0, len);
            r = -1;
        } else if (r > 0) {
            buf[r-1] = 0;
        }
    }
    write(tty, "\n", 1);
    tcsetattr(tty, TCSANOW, &old);
    close(tty);
    return r;
}

#endif /* !_WIN32 */
