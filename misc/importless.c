// Print a message on Windows without explicit imports
//   $ cc -nostdlib -o importless2.exe importless2.c
//   $ cl /GS- /utf-8 importless2.c /link /subsystem:console
//
// Supports both x86 and x64 using any C compiler. Requires at least
// Windows 7: XP and earlier do not pass the PEB pointer to the entry
// point, so it must be retrieved with assembly (one-liner).
//
// Ref: https://github.com/friendlyanon/shellcodeish
// Ref: https://old.reddit.com/r/C_Programming/comments/1d2zisl
// This is free and unencumbered software released into the public domain.
#include <stddef.h>

#define countof(a)  (iz)(sizeof(a) / sizeof(*(a)))

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef          ptrdiff_t iz;
typedef          size_t    uz;
typedef unsigned short     char16_t;
typedef          wchar_t   c16;

typedef struct {
    b32   (__stdcall *ExitProcess)(i32);
    void *(__stdcall *GetProcAddress)(u8 *, char *);
    uz    (__stdcall *GetStdHandle)(i32);
    b32   (__stdcall *WriteConsoleW)(uz, c16 *, i32, i32 *, uz);
} win32;

static win32 init(void *peb)
{
    u8  ******p   = peb;  // !!!
    u8  *kernel32 = p[3][1+8/sizeof(uz)][0][0][6];
    u32 *pe       = (u32 *)(kernel32 + *(u32 *)(kernel32 + 0x3c));
    u32 *edata    = (u32 *)(kernel32 + pe[26+sizeof(uz)]);
    u32 *addrs    = (u32 *)(kernel32 + edata[7]);
    u32 *names    = (u32 *)(kernel32 + edata[8]);
    u16 *ordinals = (u16 *)(kernel32 + edata[9]);

    win32 r = {0};
    for (i32 i = 0;; i++) {
        u8 *name = kernel32 + names[i];
        u8 *want = (u8 *)"GetProcAddress";
        for (; *name && *name==*want; name++, want++) {}
        if (*name == *want) {
            r.GetProcAddress = (void *)(kernel32 + addrs[ordinals[i]]);
            break;
        }
    }
    r.ExitProcess   = r.GetProcAddress(kernel32, "ExitProcess");
    r.GetStdHandle  = r.GetProcAddress(kernel32, "GetStdHandle");
    r.WriteConsoleW = r.GetProcAddress(kernel32, "WriteConsoleW");
    return r;
}

void mainCRTStartup(void *peb)
{
    win32 w32  = init(peb);
    uz  stdout = w32.GetStdHandle(-11);
    c16 msg[]  = u"Hello, π!\n";
    i32 len    = countof(msg) - 1;
    b32 ok     = w32.WriteConsoleW(stdout, msg, len, &len, 0);
    w32.ExitProcess(!ok);
}
