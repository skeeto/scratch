/* UTF-8 console password prompt for Windows
 * This is free and unencumbered software released into the public domain.
 */
#include <windows.h>

#ifdef _MSC_VER
#  pragma comment(lib, "crypt32.lib")
#endif

// Display prompt then read zero-terminated, UTF-8 password.
// Return password length with terminator, or zero on error.
static int
read_password(char *buf, int len, char *prompt)
{
    /* Resources that will be cleaned up */
    int pwlen = 0;
    DWORD orig = 0;
    WCHAR *wbuf = 0;
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
    wbuf = CryptMemAlloc((len - 1 + 2) * sizeof(WCHAR));
    if (!wbuf) goto done;

    /* Read and convert to UTF-8 */
    DWORD nread;
    if (!ReadConsoleW(hi, wbuf, len - 1 + 2, &nread, 0)) goto done;
    if (nread < 2) goto done;
    if (wbuf[nread-2] != '\r' || wbuf[nread-1] != '\n') goto done;
    wbuf[nread-2] = 0;  // truncate "\r\n"
    pwlen = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, len, 0, 0);

done:
    /* Exploits that operations on INVALID_HANDLE_VALUE are no-ops */
    CryptMemFree(wbuf);
    WriteConsoleA(ho, "\n", 1, 0, 0);
    SetConsoleMode(hi, orig);
    CloseHandle(ho);
    CloseHandle(hi);
    return pwlen;
}

#include <stdio.h>

int
main(void)
{
    SetConsoleOutputCP(65001);

    char password[512];
    int len = read_password(password, sizeof(password), "password: ");
    if (len) {
        for (int i = 0; i < len - 1; i++) {
            printf("%02x%c", password[i]&0xff, " \n"[i == len - 2]);
        }
        printf("%s\n", password);
        return 0;
    } else {
        printf("read_password() failed\n");
        return 1;
    }
}
