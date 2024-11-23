enum { HEAPCAP = 1<<21 };
#include "common.cpp"
extern "C" int wprintf(char16_t const *, ...);

static s8 mapfile(c16 *path)
{
    i32 share = FILE_SHARE_READ | FILE_SHARE_DELETE;
    i32 attr  = FILE_ATTRIBUTE_NORMAL;
    uz h = CreateFileW(
        path, GENERIC_READ, share, 0, OPEN_EXISTING, attr, 0
    );
    if (h == uz(-1)) {
        return {};
    }

    i64 len;
    GetFileSizeEx(h, &len);
    uz m = CreateFileMappingW(h, 0, PAGE_READONLY, i32(len>>32), i32(len), 0);
    CloseHandle(h);
    if (m == uz(-1)) {
        return {};
    }

    s8 r = {};
    r.data = MapViewOfFile(m, FILE_MAP_READ, 0, 0, len);
    CloseHandle(m);
    r.len = r.data ? len : 0;
    return r;
}

struct File {
    i32 nameoff;
    i32 dataoff;
    i32 len;
};

static s16 randname(Arena *a)
{
    u8 buf[16] = {};
    SystemFunction036(buf, countof(buf));  // RtlGenRandom

    s16 r  = {};
    r.len  = countof(buf);
    r.data = alloc<c16>(a, countof(buf));
    for (i32 i = 0; i < countof(buf); i++) {
        static u8 b64[] = "abcdefghijklmnopqrstuvwxyz"
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                          "0123456789" "+-";
        r.data[i] = b64[buf[i]&63];
    }
    return r;
}

static b32 dumpfile(c16 *path, s8 s)
{
    i32 share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    i32 attr  = FILE_ATTRIBUTE_NORMAL;
    uz h = CreateFileW(
        path, GENERIC_WRITE, share, 0, CREATE_ALWAYS, attr, 0
    );
    if (h == uz(-1)) {
        return 0;
    }

    b32 ok = 1;
    for (iz off = 0; ok && off<s.len;) {
        i32 len = trunc32(s.len - off);
        ok = WriteFile(h, s.data+off, len, &len, 0);
        off += len;
    }
    CloseHandle(h);
    return ok;
}

static i32 run(Arena a)
{
    i32 ret = i32(0x80000000);

    s16 path = getexepath(&a);
    s8  data = mapfile(path.data);
    if (!data.data) {
        return ret;  // TODO: display error
    }

    s16 random = randname(&a);
    s16 tmpdir = gettmppath(&a);
    tmpdir = concat(&a, tmpdir, s16{u"loader-"});
    tmpdir = concat(&a, tmpdir, random);
    tmpdir = concat(&a, tmpdir, s16{u"\\"});
    {
        Arena tmp = a;
        s16 path = concat(&tmp, tmpdir, s16{u"\0"});
        if (!CreateDirectoryW(path.data, 0)) {
            return ret;  // TODO: display error
        }
        // TODO: Now that cleanup is required, use SetConsoleCtrlHandler
        // to ignore CTRL-c while so that cleanup proceeds regardless.
    }

    i32   len   = *(i32 *)(data.data + data.len - 4);
    u8   *base  = data.data + data.len - len;
    File *files = (File *)base;

    b32 ok = 1;
    for (i32 i = 0; ok && files[i].nameoff; i++) {
        Arena tmp  = a;
        c16  *name = (c16 *)(base + files[i].nameoff);
        s8    data = {};
        data.data  = base + files[i].dataoff;
        data.len   = files[i].len;
        c16 *path  = concat(&tmp, tmpdir, s16{name}).data;
        ok         = dumpfile(path, data);  // TODO: display error
    }

    if (ok) {
        Arena tmp = a;
        c16  *cmd = GetCommandLineW();
        c16  *exe = (c16 *)(base + files[0].nameoff);
        c16  *app = concat(&tmp, tmpdir, s16{exe}).data;
        SI   *si  = alloc<SI>(&tmp);
        PI   *pi  = alloc<PI>(&tmp);
        if (CreateProcessW(app, cmd, 0, 0, 1, 0, 0, 0, si, pi)) {
            WaitForSingleObject(pi->process, -1);
            GetExitCodeProcess(pi->process, &ret);
        }
    }

    // Cleanup: no error checks necessary
    for (i32 i = 0; files[i].nameoff; i++) {
        Arena tmp = a;
        c16  *name = (c16 *)(base + files[i].nameoff);
        c16  *path = concat(&tmp, tmpdir, s16{name}).data;
        DeleteFileW(path);
    }
    {
        Arena tmp = a;
        c16 *path = concat(&tmp, tmpdir, s16{u"\0"}).data;
        RemoveDirectoryW(path);
    }
    return ret;
}
