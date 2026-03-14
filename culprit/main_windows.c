#include "culprit.c"

// Win32 implementation

typedef struct {
    i32 attr;
    i32 create[2];
    i32 access[2];
    i32 write[2];
    i32 size[2];
    i32 _1[2];
    c16 name[260];
    c16 altname[14];
    i32 _2[2];
} FindData;

typedef struct {
    i32 pid;
    i32 time[2];
    c16 name[256];
    c16 service[64];
    i32 type;
    i32 status;
    i32 sid;
    i32 restartable;
} ProcessInfo;

#define W32 [[gnu::stdcall, gnu::dllimport]]
W32 i32     CloseHandle(uz);
W32 c16   **CommandLineToArgvW(c16 *, i32 *);
W32 uz      CreateFileW(c16 *, i32, i32, uz, i32, i32, uz);
W32 void    ExitProcess(i32);
W32 uz      FindFirstFileW(c16 *, FindData *);
W32 i32     FindNextFileW(uz, FindData *);
W32 c16    *GetCommandLineW();
W32 uz      GetStdHandle(i32);
W32 i32     NtQueryInformationFile(uz, iz *, void *, i32, i32);
W32 uz      OpenProcess(i32, i32, i32);
W32 i32     QueryFullProcessImageNameW(uz, i32, c16 *, i32 *);
W32 i32     RmEndSession(i32);
W32 i32     RmGetList(i32, i32 *, i32 *, ProcessInfo *, i32 *);
W32 i32     RmRegisterResources(i32, i32, c16 **, uz, uz, uz, uz);
W32 i32     RmStartSession(i32 *, i32, c16 *);
W32 i32     WriteConsoleW(uz, c16 *, i32, i32 *, uz);
W32 i32     WriteFile(uz, u8 *, i32, i32 *, uz);

enum {
    FileProcessIdsUsingFileInformation = 47,
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
    FILE_ATTRIBUTE_NORMAL = 0x80,
    FILE_READ_ATTRIBUTES  = 0x80,
    FILE_FLAG_BACKUP_SEMANTICS = 0x2000000,
    FILE_SHARE_ALL = 7,
    OPEN_EXISTING = 3,
    STATUS_INFO_LENGTH_MISMATCH = 0xc0000004,
    ERROR_MORE_DATA = 234,
};

static Pids filepids(Plt *, Arena *a, c16 **paths, i32 npaths)
{
    Pids r = {};

    i32 h = 0;
    i32 err = RmStartSession(&h, 0, (c16[33]){});
    if (err) {
        return r;
    }

    err = RmRegisterResources(h, npaths, paths, 0, 0, 0, 0);
    if (err) {
        RmEndSession(h);
        return r;
    }

    ProcessInfo *buf = new(a, 0, ProcessInfo);
    i32          len = 0;
    i32          cap = trunc32((a->end - (u8 *)buf) / (iz)sizeof(ProcessInfo));
    err = RmGetList(h, &len, &cap, buf, &(i32){});
    RmEndSession(h);
    if (err) {
        return r;
    }

    r.len  = len;
    r.pids = (i32 *)buf;
    for (i32 i = 0; i < r.len; i++) {
        __builtin_memcpy(r.pids+i, &buf[i].pid, (iz)sizeof(i32));
    }

    a->beg += r.len * (iz)sizeof(i32);
    return r;
}

static Pids dirpids(Plt *, Arena *a, c16 *path)
{
    Pids r = {};

    uz h = CreateFileW(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_ALL,
        0,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        0
    );
    if (h == (uz)-1) {
        return r;
    }

    i32 *buf     = (i32 *)new(a, 0, uz);
    i32  len     = trunc32(a->end - (u8 *)buf);
    iz   info[2] = {};
    i32  err = NtQueryInformationFile(
        h, info, buf, len, FileProcessIdsUsingFileInformation
    );
    CloseHandle(h);
    if (err) {
        return r;  // OOM
    }

    r.len  = buf[0];
    r.pids = buf;
    for (i32 i = 0; i < r.len; i++) {
        r.pids[i] = r.pids[2+i*2];
    }

    a->beg += r.len * (iz)sizeof(i32);
    return r;
}

static Str16 pidname(Plt *, Arena *a, i32 pid)
{
    Str16 r = {};
    uz    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if (!h) {
        return r;
    }

    c16 *buf = new(a, 0, c16);
    i32  len = trunc32((a->end - (u8 *)buf) / (iz)sizeof(c16));
    i32  ok  = QueryFullProcessImageNameW(h, 0, buf, &len);
    CloseHandle(h);
    if (!ok) {
        return r;  // OOM
    }

    r.data = buf;
    r.len  = len;
    a->beg += r.len * (iz)sizeof(c16);
    return r;
}

static i32 write16(Plt *, i32 fd, Str16 s)
{
    uz h = GetStdHandle(-10 - fd);
    return !!WriteConsoleW(h, s.data, trunc32(s.len), &(i32){}, 0);
}

struct Plt {
    // nothing yet
};

[[gnu::stdcall]]
i32 mainCRTStartup()
{
    static u8 mem[1<<24];
    c16  *cmd  = GetCommandLineW();
    i32   argc = 0;
    c16 **argv = CommandLineToArgvW(cmd, &argc);
    i32   code = app(0, argc, argv, mem, sizeof(mem));
    ExitProcess(code);
    __builtin_unreachable();
}
