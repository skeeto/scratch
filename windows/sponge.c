// Sponge for Windows: soak up standard input and then write to a file
//
// usage: $ sponge [-a] FILE
// build: $ cc -nostartfiles -o sponge.exe sponge.c
//        $ cl /GS- sponge.c /link /subsystem:console kernel32.lib shell32.lib
//
// Supports wide paths, arguments, and errors. CRT-free. Unfortunately
// because nearly every program on Windows, including system utilities,
// exclusively locks the files they touch, this program is less useful
// than it could otherwise be. Often the file being preserved is still
// locked when sponge attempts to replace/update it. Oh well.
//
// This is free and unencumbered software released into the public domain.

#define MAX_PATH  260
#define INVALID_HANDLE_VALUE (void *)-1
#define FILE_BEGIN 0
#define FILE_END   2
#define GENERIC_READ  0x80000000
#define GENERIC_WRITE 0x40000000
#define FILE_SHARE_READ   0x00000001
#define FILE_SHARE_DELETE 0x00000004
#define CREATE_ALWAYS 2
#define OPEN_ALWAYS   4
#define FILE_ATTRIBUTE_NORMAL     0x00000080
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000

typedef unsigned short char16_t;

#define W32(r) __declspec(dllimport) r __stdcall
W32(void *)      CreateFileW(char16_t *, int, int, void *, int, int, void *);
W32(int)         CreateHardLinkW(char16_t *, char16_t *, void *);
W32(char16_t **) CommandLineToArgvW(char16_t *, int *);
W32(int)         DeleteFileW(char16_t *);
W32(void *)      GetCommandLineW(void);
W32(int)         GetConsoleMode(void *, int *);
W32(void *)      GetStdHandle(int);
W32(int)         GetTempFileNameW(char16_t *, char16_t *, int, char16_t *);
W32(int)         ReadFile(void *, void *, int, int *, void *);
W32(int)         SetFilePointer(void *, long, long *, int);
W32(int)         WriteConsoleW(void *, void *, int, int *, void *);
W32(int)         WriteFile(void *, void *, int, int *, void *);

static int copy(void *dst, void *src, void *buf, int cap)
{
    for (;;) {
        int len;
        ReadFile(src, buf, cap, &len, 0);
        if (!len) {
            return 1;
        }
        if (!WriteFile(dst, buf, len, &len, 0)) {
            return 0;
        }
    }
}

static int dirsep(char16_t c)
{
    return c=='/' || c=='\\';
}

static void dirname(char16_t *dst, char16_t *src)
{
    char16_t *last = 0;
    for (char16_t *p = src; *p; p++) {
        last = dirsep(*p) ? p : last;
    }

    if (!last || last-src>=MAX_PATH) {
        *dst++ = '.';
    } else {
        for (char16_t *p = src; p <= last; p++) {
            *dst++ = *p;
        }
    }
    *dst = 0;
}

static int appendflag(char16_t *s)
{
    return s[0]=='-' && s[1]=='a' && s[2]==0;
}

typedef struct {
    void *buf;
    int cap;
    int len;
    int err;
    enum {BUF8, BUF16} type;
} Out;

static Out newout(char16_t *buf, int cap)
{
    Out out = {0};
    out.buf = buf;
    out.cap = cap;
    void *stderr = GetStdHandle(-11);
    int mode;
    out.type = GetConsoleMode(stderr, &mode) ? BUF16 : BUF8;
    return out;
}

static void flush(Out *out)
{
    if (!out->err) {
        int len;
        void *stderr = GetStdHandle(-11);
        switch (out->type) {
        case BUF8:
            out->err |= !WriteFile(stderr, out->buf, out->len, &len, 0);
            break;
        case BUF16:
            out->err |= !WriteConsoleW(stderr, out->buf, out->len/2, &len, 0);
            break;
        }
    out->len = 0;
    }
}

static void append(Out *out, void *buf, int len)
{
    char *beg = buf;
    char *end = beg + len;
    while (!out->err && beg<end) {
        int avail = out->cap - out->len;
        int count = end-beg<avail ? (int)(end-beg) : avail;
        char *dst = (char *)out->buf + out->len;
        for (int i = 0; i < count; i++) {
            dst[i] = beg[i];
        }
        beg += count;
        out->len += count;
        if (out->len == out->cap) {
            flush(out);
        }
    }
}

#define PRINT(out, s) print(out, s, sizeof(s)/2-1)
static void print(Out *out, char16_t *s, int len)
{
    if (len < 0) {
        for (len = 0; s[len]; len++) {}
    }
    switch (out->type) {
    case BUF8:
        for (int i = 0; i < len; i++) {
            char c[3], *p = c;
            if (s[i] < 0x80) {
                *p++ = (char )s[i];
            } else if (s[i] < 0x800) {
                *p++ = (char)(0xc0 | (s[i] >>  6));
                *p++ = (char)(0x80 | (s[i] >>  0 & 63));
            } else {
                *p++ = (char)(0xe0 | (s[i] >> 12));
                *p++ = (char)(0x80 | (s[i] >>  6 & 63));
                *p++ = (char)(0x80 | (s[i] >>  0 & 63));
            }
            append(out, c, (int)(p-c));
        }
        break;
    case BUF16:
        append(out, s, len*2);
        break;
    }
}

int mainCRTStartup(void)
{
    char16_t *destpath = 0;
    static char16_t buf[1<<14];
    void *stdin  = GetStdHandle(-10);
    enum {MODE_TRUNC, MODE_APPEND} mode = MODE_TRUNC;
    Out stderr[1] = {newout(buf, sizeof(buf))};

    int argc;
    char16_t *cmdline = GetCommandLineW();
    char16_t **argv = CommandLineToArgvW(cmdline, &argc);
    switch (argc) {
    case 2: if (appendflag(argv[1])) {
                break;
            }
            destpath = argv[1];
            break;
    case 3: if (!appendflag(argv[1])) {
                break;
            }
            mode = MODE_APPEND;
            destpath = argv[2];
    }
    if (!destpath) {
        PRINT(stderr, L"sponge: ");
        PRINT(stderr, L"wrong number of arguments\n");
        PRINT(stderr, L"usage: sponge [-a] <FILE>\n");
        flush(stderr);
        return 1;
    }

    char16_t destdir[MAX_PATH];
    dirname(destdir, destpath);
    char16_t temppath[MAX_PATH];
    GetTempFileNameW(destdir, L"sponge", 0, temppath);
    void *temp = CreateFileW(
        temppath,
        GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_DELETE,
        0,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_DELETE_ON_CLOSE,
        0
    );
    if (temp == INVALID_HANDLE_VALUE) {
        PRINT(stderr, L"sponge: ");
        PRINT(stderr, L"could not open temporary file: ");
        print(stderr, temppath, -1);
        PRINT(stderr, L"\n");
        flush(stderr);
        return 1;
    }

    copy(temp, stdin, buf, sizeof(buf));

    switch (mode) {
    case MODE_TRUNC:;
        DeleteFileW(destpath);
        if (!CreateHardLinkW(destpath, temppath, 0)) {
            PRINT(stderr, L"sponge: ");
            PRINT(stderr, L"could not create hard link: ");
            print(stderr, destpath, -1);
            PRINT(stderr, L"\n");
            flush(stderr);
            return 1;
        }
        break;

    case MODE_APPEND:;
        void *out = CreateFileW(
            destpath,
            GENERIC_WRITE,
            FILE_SHARE_READ|FILE_SHARE_DELETE,
            0,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0
        );
        if (out == INVALID_HANDLE_VALUE) {
            PRINT(stderr, L"sponge: ");
            PRINT(stderr, L"could not open output file: ");
            print(stderr, destpath, -1);
            PRINT(stderr, L"\n");
            flush(stderr);
            return 1;
        }
        int err = 0;
        err |= err ? err : SetFilePointer(temp, 0, 0, FILE_BEGIN) == -1;
        err |= err ? err : SetFilePointer(out, 0, 0, FILE_END) == -1;
        err |= err ? err : !copy(out, temp, buf, sizeof(buf));
        if (err) {
            PRINT(stderr, L"sponge: ");
            PRINT(stderr, L"error writing output\n");
            flush(stderr);
            return 1;
        }
        break;
    }
    return 0;
}
