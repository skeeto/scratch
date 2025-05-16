// SMACX crash patcher
//   $ cc -nostartfiles -Oz -s -o smacxfix.exe smacxfix.c
// Drag and drop terranx.exe onto smacxfix.exe. Does not make a backup.
//
// A super portable build that works on Windows 95:
//   $ i686-w64-mingw32-gcc -nostartfiles -march=i386 -Oz -s
//         -o smacxfix.exe smacxfix.c
//
// Equivalent to this xxd patch:
//   $ crc32 terranx.exe
//   f3b52d3d terranx.exe
//   $ echo 1a6b1b: e9f1000000 | xxd -r - terranx.exe
//   $ crc32 terranx.exe
//   6287d026 terranx-patched.exe
//
// Equivalent to the Adamite patcher, but 0.001% of its size.
//
// Ref: https://www.youtube.com/watch?v=0nEy4iAdbME
// Ref: https://github.com/nathan-baggs/Adamite
// This is free and unencumbered software released into the public domain.
#include <stddef.h>

#define lenof(a)    (i32)(sizeof(a) / sizeof(*(a)))
#define s(s)        (Str){(u8 *)s, lenof(s)-1}

typedef unsigned char       u8;
typedef unsigned short      c16;
typedef int                 i32;
typedef unsigned long long  u64;
typedef size_t              uz;

enum {
    FILE_SHARE_ALL          = 7,
    GENERIC_READ            = (i32)0x80000000,
    GENERIC_WRITE           = (i32)0x40000000,
    OPEN_EXISTING           = 3,
};

#define W32 __attribute((dllimport)) __stdcall
W32 c16   **CommandLineToArgvW(c16 *, i32 *);
W32 c16    *GetCommandLineW();
W32 uz      CreateFileW(c16 *, i32, i32, uz, i32, i32, uz);
W32 void    ExitProcess(i32) __attribute((noreturn));
W32 uz      GetStdHandle(i32);
W32 i32     ReadFile(uz, u8 *, i32, i32 *, uz);
W32 i32     SetFilePointer(uz, i32, i32 *, i32);
W32 i32     WriteFile(uz, u8 *, i32, i32 *, uz);

typedef struct {
    u8 *data;
    i32 len;
} Str;

static void wait()
{
    ReadFile(GetStdHandle(-10), &(u8){0}, 1, &(i32){0}, 0);
}

static void print(i32 fd, Str s)
{
    uz h = GetStdHandle(-10 - fd);
    WriteFile(h, s.data, s.len, &(i32){0}, 0);
}

static void fatal(Str msg)
{
    print(2, s("ERROR: "));
    print(2, msg);
    print(2, s("\n"));
    wait();
    ExitProcess(1);
}

static void success(Str msg)
{
    print(1, s("SUCCESS: "));
    print(1, msg);
    print(1, s("\n"));
    wait();
    ExitProcess(0);
}

void __stdcall mainCRTStartup()
{
    c16  *cmd  = GetCommandLineW();
    i32   argc = 0;
    c16 **argv = CommandLineToArgvW(cmd, &argc);

    if (argc != 2) {
        fatal(s("usage: smacxfix.exe terranx.exe"));
    }

    i32 access = GENERIC_READ | GENERIC_WRITE;
    i32 share  = FILE_SHARE_ALL;
    i32 create = OPEN_EXISTING;
    uz  exe    = CreateFileW(argv[1], access, share, 0, create, 0, 0);
    if (exe == (uz)-1) {
        fatal(s("failed to open input file"));
    }

    enum { cap = 3084288 };
    static u8 buf[cap+1];  // extra byte detects too-large input
    i32 len = 0;
    if (!ReadFile(exe, buf, lenof(buf), &len, 0)) {
        fatal(s("failed to read input file"));
    }
    if (len != cap) {
        fatal(s("input file mismatch (size)"));
    }

    u64 sum = 0x100;
    for (i32 i = 0; i < len; i++) {
        sum ^= buf[i];
        sum *= 1111111111111111111;
    }
    if (sum == 0x373afe16ea73cce2) {
        // TODO: maybe unpatch and restore?
        success(s("EXE is already patched"));
    }
    if (sum != 0x27216079c5be2af4) {
        fatal(s("input file mismatch (checksum)"));
    }

    if (SetFilePointer(exe, 0x1a6b1b, &(i32){0}, 0) == -1) {
        fatal(s("failed to seek input file"));
    }

    u8 patch[] = {0xe9, 0xf1, 0x00, 0x00, 0x00};
    if (!WriteFile(exe, patch, lenof(patch), &(i32){0}, 0)) {
        fatal(s("failed to patch input file"));
    }

    success(s("crash bug patched"));
}
