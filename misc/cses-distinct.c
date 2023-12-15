// Distinct Numbers
// https://cses.fi/problemset/task/1621
// This is free and unencumbered software released into the public domain.
typedef unsigned char      u8;
typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef __PTRDIFF_TYPE__   size;
typedef __UINTPTR_TYPE__   uptr;

typedef struct {
    u8  *data;
    size len;
} s8;

static b32 digit(u8 c)
{
    return (unsigned)c-'0' <= 9;
}

typedef struct {
    i32 value;
    s8  remain;
} i32parsed;

static i32parsed parse(s8 s)
{
    i32parsed r = {0};
    u8 *p = s.data;
    u8 *e = s.data + s.len;
    for (; !digit(*p); p++) {}
    while (p < e) {
        if (!digit(*p)) {
            break;
        }
        r.value = r.value*10 + *p++ - '0';
    }
    r.remain.data = p;
    r.remain.len = e - p;
    return r;
}

static s8 encode(s8 s, i32 x)
{
    u8 *e = s.data + s.len;
    u8 *b = e;
    *--b = '\n';
    do {
        *--b = (u8)(x%10) + '0';
    } while (x /= 10);

    s8 r = {0};
    r.data = b;
    r.len = e - b;
    return r;
}

static s8 solve(s8 input)
{
    i32parsed p = parse(input);
    i32 len = p.value;

    i32 count = 0;
    enum { tabsize = 18 };
    static i32 seen[1<<tabsize] = {0};

    for (i32 i = 0; i < len; i++) {
        p = parse(p.remain);
        u64 hash = p.value*1111111111111111111u;
        u32 mask = ((u32)1<<tabsize) - 1;
        u32 step = (u32)(hash>>(64 - tabsize)) | 1;
        for (i32 index = (i32)hash;;) {
            index = (index + step) & mask;
            if (seen[index] == p.value) {
                break;
            } else if (!seen[index]) {
                seen[index] = p.value;
                count++;
                break;
            }
        }
    }

    return encode(input, count);
}

#if _WIN32
#define W32 __attribute((dllimport, stdcall))
W32 i32  GetStdHandle(i32);
W32 b32  ReadFile(uptr, u8 *, i32, i32 *, void *);
W32 b32  WriteFile(uptr, u8 *, i32, i32 *, void *);
W32 void ExitProcess(i32);

void mainCRTStartup(void)
{
    static u8 buf[1<<24];
    i32 len;
    ReadFile(GetStdHandle(-10), buf, sizeof(buf), &len, 0);

    s8 input = {0};
    input.data = buf;
    input.len = len;

    s8 output = solve(input);

    WriteFile(GetStdHandle(-11), output.data, (i32)output.len, &len, 0);
    ExitProcess(0);
}

#elif __linux
static s8 fullread(s8 s)
{
    size off = 0;
    while (off < s.len) {
        size r;
        asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(0), "D"(0), "S"(s.data+off), "d"(s.len-off)
            : "rcx", "r11", "memory"
        );
        if (r < 1) {
            break;
        }
        off += r;
    }
    s.len = off;
    return s;
}

static b32 fullwrite(s8 s)
{
    size off = 0;
    while (off < s.len) {
        size r;
        asm volatile (
            "syscall"
            : "=a"(r)
            : "a"(0), "D"(0), "S"(s.data+off), "d"(s.len-off)
            : "rcx", "r11", "memory"
        );
        if (r < 1) {
            return 0;
        }
        off += r;
    }
    return 1;
}

int main()
{
    static u8 buf[1<<24];
    s8 input = {0};
    input.data = buf;
    input.len = fullread(buf);

    s8 output = solve(input);

    fullwrite(output);
    asm volatile ("syscall" : : "a"(60), "D"(0));
    __builtin_unreachable();
}
#endif
