// This is free and unencumbered software released into the public domain.
#include "glove-lookup.c"

#define W32(r) __declspec(dllimport) r __stdcall
W32(i32)    CreateFileMappingA(uptr, uptr, i32, i32, i32, uptr);
W32(void)   ExitProcess(i32);
W32(b32)    GetFileSizeEx(uptr, i64 *);
W32(i32)    GetStdHandle(i32);
W32(void *) MapViewOfFile(uptr, i32, i32, i32, size);
W32(b32)    WriteFile(uptr, void *, i32, i32 *, uptr);
W32(u16 *)  GetCommandLineW(void);
W32(u16 **) CommandLineToArgvW(u16 *, i32 *);
W32(i32)    WideCharToMultiByte(i32, i32, u16 *, i32, u8 *, i32, uptr, uptr);
W32(void *) VirtualAlloc(void *, size, i32, i32);

static b32 fullwrite(u8 *buf, i32 len)
{
    i32 stdout = GetStdHandle(-11);
    return WriteFile(stdout, buf, len, &len, 0);
}

static s8 makes8(u16 *w, arena *perm)
{
    enum {
        CP_UTF8 = 65001,
    };
    s8 s = {0};
    s.len = WideCharToMultiByte(CP_UTF8, 0, w, -1, 0, 0, 0, 0);
    s.data = new(perm, u8, s.len);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data, (i32)s.len, 0, 0);
    s.len--;
    return s;
}

static b32 entry(void)
{
    enum {
        FILE_MAP_READ  = 4,
        PAGE_READONLY  = 2,
        PAGE_READWRITE = 4,
        MEM_ALLOCATE   = 0x3000,
    };

    b32 err = 0;
    i32 stdin  = GetStdHandle(-10);
    i32 mapping = CreateFileMappingA(stdin, 0, PAGE_READONLY, 0, 0, 0);
    err |= !mapping;
    void *idx = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    err |= !idx;
    if (err) {
        return 1;
    }

    size cap = 1<<20;
    arena scratch = {0};
    scratch.beg = VirtualAlloc(0, cap, MEM_ALLOCATE, PAGE_READWRITE);
    scratch.end = scratch.beg + cap;

    u16 *cmdline = GetCommandLineW();
    i32 argc;
    u16 **argvw = CommandLineToArgvW(cmdline, &argc);

    s8 *argv = new(&scratch, s8, argc);
    for (i32 i = 0; i < argc; i++) {
        argv[i] = makes8(argvw[i], &scratch);
    }
    return run(argc, argv, idx, scratch);
}

void mainCRTStartup(void)
{
    b32 err = entry();
    ExitProcess(err);
}
