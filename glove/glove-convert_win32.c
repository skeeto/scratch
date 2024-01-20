// This is free and unencumbered software released into the public domain.
#include "glove.c"

#define W32(r) __declspec(dllimport) r __stdcall
W32(i32)    CreateFileMappingA(uptr, uptr, i32, i32, i32, uptr);
W32(void)   ExitProcess(i32);
W32(b32)    GetFileSizeEx(uptr, i64 *);
W32(i32)    GetStdHandle(i32);
W32(void *) MapViewOfFile(uptr, i32, i32, i32, size);
W32(void *) VirtualAlloc(void *, size, i32, i32);
W32(b32)    WriteFile(uptr, void *, i32, i32 *, uptr);

static b32 run(void)
{
    enum {
        FILE_MAP_READ  = 4,
        PAGE_READONLY  = 2,
        PAGE_READWRITE = 4,
        MEM_ALLOCATE   = 0x3000,
    };

    i32 stdin  = GetStdHandle(-10);
    i32 stdout = GetStdHandle(-11);

    b32 err = 0;
    i64 len;
    err |= !GetFileSizeEx(stdin, &len);
    i32 mapping = CreateFileMappingA(stdin, 0, PAGE_READONLY, 0, 0, 0);
    err |= !mapping;
    void *data = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    err |= !data;

    glove_specs s;
    glove_examine(&s, data, len);
    byte *db = VirtualAlloc(0, s.db_size, MEM_ALLOCATE, PAGE_READWRITE);
    err |= !db;

    if (err) {
        return 1;
    }

    glove_make_db(db, &s, data, len);
    for (size off = 0; !err && off<s.db_size;) {
        i32 max = 1<<30;
        i32 amt = s.db_size-off > max ? max : (i32)(s.db_size-off);
        err |= !WriteFile(stdout, db+off, amt, &amt, 0);
        off += amt;
    }
    return err;
}

void mainCRTStartup(void)
{
    b32 err = run();
    ExitProcess(err);
}
