using u8  = unsigned char;
using b32 = decltype(0);
using i32 = decltype(0);
using c16 = decltype(u'0');
using i64 = decltype(0LL);
using iz  = decltype((u8 *)0 - (u8 *)0);
using uz  = decltype(sizeof(0));

#define assert(c)   while (!(c)) *(volatile i32 *)0 = 0
#define countof(a)  (iz)(sizeof(a) / sizeof(*(a)))

template<typename T>
void *operator new(uz, T *p) { return p; }

struct Arena {
    u8 *beg;
    u8 *end;
};

template<typename T>
T *alloc(Arena *a, iz count = 1)
{
    iz size = sizeof(T);
    iz pad  = -(uz)a->beg & (alignof(T) - 1);
    assert(count < (a->end - a->beg - pad)/size);  // TODO handle OOM
    T *r = (T *)(a->beg + pad);
    a->beg += pad + count*size;
    for (iz i = 0; i < count; i++) {
        new (r+i) T();
    }
    return r;
}

template<typename T, typename C>
struct Str {
    union {
        T       *data = 0;
        C const *cdata;
    };
    iz len = 0;

    Str() = default;

    Str(Arena *a, Str s) : data{alloc<T>(a, s.len)}, len{s.len}
    {
        for (iz i = 0; i < len; i++) {
            data[i] = s[i];
        }
    }

    template<iz N>
    Str(C const (&s)[N]) : cdata{s}, len{N-1} {}

    Str(T *s) : data{s} { while (s[len++]) {} }

    c16 &operator[](iz i) { return data[i]; }
};

using s16 = Str<c16, c16>;
using s8  = Str<u8, char>;

template<typename T>
T trunc(T s, iz len)
{
    s.len = len;
    return s;
}

template<typename T>
T concat(Arena *a, T head, T tail)
{
    if (a->beg != (u8 *)(head.data+head.len)) {
        head = T{a, head};
    }
    head.len += T{a, tail}.len;
    return head;
}

inline i32 trunc32(iz n)
{
    i32 max = 0x7fffffff;
    return max<n ? max : i32(n);
}

static b32 dirsep(c16 c)
{
    return c=='/' || c=='\\';
}

inline s16 dirname(s16 s)
{
    for (; s.len && !dirsep(s[s.len-1]); s.len--) {}
    return s;
}

inline s16 basename(s16 s)
{
    iz len = s.len;
    for (; len && !dirsep(s[len-1]); len--) {}
    s.data += len;
    s.len  -= len;
    return s;
}


// Win32

enum : i32 {
    GENERIC_READ    = i32(0x80000000),
    GENERIC_WRITE   = i32(0x40000000),

    FILE_SHARE_READ   = 1,
    FILE_SHARE_WRITE  = 2,
    FILE_SHARE_DELETE = 4,

    CREATE_NEW    = 1,
    CREATE_ALWAYS = 2,
    OPEN_EXISTING = 3,
    OPEN_ALWAYS   = 4,

    FILE_ATTRIBUTE_NORMAL = 0x80,

    MEM_COMMIT  = 0x1000,
    MEM_RESERVE = 0x2000,

    PAGE_READONLY  = 0x02,
    PAGE_READWRITE = 0x04,

    FILE_MAP_READ = 4,
};

struct SI {
    i32 cb = sizeof(SI);
    uz  a, b, c;
    i32 d, e, f, g, h, i, j, k, l;
    uz  m, n, o, p;
};

struct PI {
    uz  process;
    uz  thread;
    i32 pid;
    i32 tid;
};

#define W32(r, p) extern "C" r __stdcall p noexcept
W32(b32,    CloseHandle(uz));
W32(c16 **, CommandLineToArgvW(c16 *, i32 *));
W32(b32,    CreateDirectoryW(c16 *, uz));
W32(uz,     CreateFileMappingW(uz, uz, i32, i32, i32, uz));
W32(uz,     CreateFileW(c16 *, i32, i32, uz, i32, i32, uz));
W32(b32,    CreateProcessW(c16*,c16*,uz,uz,b32,i32,c16*,c16*,SI*,PI*));
W32(b32,    DeleteFileW(c16 *));
W32(void,   ExitProcess[[noreturn]](i32));
W32(c16 *,  GetCommandLineW(void));
W32(i32,    GetExitCodeProcess(uz, i32 *));
W32(b32,    GetFileSizeEx(uz, i64 *));
W32(i32,    GetModuleFileNameW(uz, c16 *, i32));
W32(uz,     GetStdHandle(i32));
W32(i32,    GetTempPathW(i32, c16 *));
W32(u8 *,   MapViewOfFile(uz, i32, i32, i32, iz));
W32(b32,    ReadFile(uz, u8 *, i32, i32 *, uz));
W32(b32,    RemoveDirectoryW(c16 *));
W32(u8,     SystemFunction036(u8 *, i32));
W32(u8 *,   VirtualAlloc(uz, iz, i32, i32));
W32(i32,    WaitForSingleObject(uz, i32));
W32(b32,    WriteFile(uz, u8 *, i32, i32 *, uz));

inline s16 getexepath(Arena *a)
{
    iz avail = a->end - a->beg;
    s16 r  = {};
    r.data = alloc<c16>(a, 0);
    r.len  = GetModuleFileNameW(0, r.data, trunc32(avail));
    a->beg = (u8 *)(r.data + r.len);
    return r;
}

inline s16 gettmppath(Arena *a)
{
    iz avail = a->end - a->beg;
    s16 r  = {};
    r.data = alloc<c16>(a, 0);
    r.len  = GetTempPathW(trunc32(avail), r.data);
    a->beg = (u8 *)(r.data + r.len);
    return r;
}

static i32 run(Arena);

extern "C" i32 __stdcall mainCRTStartup(uz)
{
    iz    cap = HEAPCAP;
    u8   *mem = VirtualAlloc(0, cap, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    Arena a   = {mem, mem+cap};
    i32   r   = run(a);
    ExitProcess(r);
}
