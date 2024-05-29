// Print a message on Windows without explicit imports
//   $ cc -nostdlib -o importless.exe importless.c
//   $ cl /GS- /utf-8 importless.c /link /subsystem:console
// Supports both x86 and x64 using any C compiler.
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

typedef struct dll dll;
struct dll {
    dll *next;
    uz   pad1[5];
    uz   base;
    uz   entry;
    iz   size;
    uz   pad2[1];
    c16 *path;
};

typedef struct {
    u8   pad1[8];
    uz   pad2[1];
    dll *next;
} ldr;

typedef struct {
    u8   pad1[16];
    uz  *console;
    i32  flags;
    uz   stdin;
    uz   stdout;
    uz   stderr;
    uz   pad2[6];
    c16 *image;
    uz   pad3[1];
    c16 *cmdline;
    c16 *env;
} params;

typedef struct {
    u8      pad1[4];
    uz      pad2[2];
    ldr    *ldr;
    params *params;
} peb;

typedef struct {
    u8  magic[4];
    u8  coff[20];
    uz  pad1[4];
    u8  pad2[80];
    u32 edataoff;
} pe;

typedef struct {
    u32 flags;
    u32 datetime;
    u32 version;
    u32 name;
    i32 ordinalbase;
    i32 nentries;
    i32 nnames;
    u32 addroff;
    u32 nameoff;
    u32 ordoff;
} edata;

static b32 equals(char *a, char *b)
{
    for (; *a && *a==*b; a++, b++)  {}
    return *a == *b;
}

void mainCRTStartup(peb *peb)
{
    // Locate kernel32.dll .edata
    u8    *kernel32 = (u8    *)peb->ldr->next->next->next->base;
    pe    *header   = (pe    *)(kernel32 + *(u32 *)(kernel32 + 0x3c));
    edata *exports  = (edata *)(kernel32 + header->edataoff);
    u32   *addrs    = (u32   *)(kernel32 + exports->addroff);
    u32   *names    = (u32   *)(kernel32 + exports->nameoff);
    u16   *ordinals = (u16   *)(kernel32 + exports->ordoff);

    // Search .edata for GetProcAddress
    void *(__stdcall *GetProcAddress)(void *, char *) = 0;
    for (i32 i = 0; i < exports->nnames; i++) {
        char *name = (char *)(kernel32 + names[i]);
        if (equals(name, "GetProcAddress")) {
            GetProcAddress = (void *)(kernel32 + addrs[ordinals[i]]);
        }
    }

    // Locate the functions we need to call
    b32 (__stdcall *WriteConsoleW)(uz, c16 *, i32, i32 *, uz);
    WriteConsoleW = GetProcAddress(kernel32, "WriteConsoleW");
    b32 (__stdcall *ExitProcess)(i32);
    ExitProcess = GetProcAddress(kernel32, "ExitProcess");

    c16 msg[] =
        u"If you wish to make an apple pie from scratch you must "
        u"first invent the universe 🍎🥧🌌\n";
    i32 len = countof(msg) - 1;
    b32 ok = WriteConsoleW(peb->params->stdout, msg, len, &len, 0);
    ExitProcess(!ok);
}
