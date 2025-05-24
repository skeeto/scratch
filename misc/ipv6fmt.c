// ipv6fmt -- format IPv6 addresses for sort
//
// Formats IPv6 addresses for lexicographic sort (-e, "exploded"). Given
// -c ("compress"), formats addresses in the canonical format, e.g. undo
// an explode. Field separation is compatible with "sort" and designed
// to augment it. Given, say, simple CSV with IPv6 addresses in its 4th
// column over which we'd like to sort:
//
// $ ipv6fmt -k4 -t, <data.csv | sort -k4 -t, | ipv6fmt -ck4 -t, >sorted.csv
//
// Or in the simple case, a list of IPv6 addresses:
//
// $ printf '0:1::\n::2:1\n' | ipv6fmt | sort | ipv6fmt -c
//
// Does not accept paths nor positional arguments. Always processes
// standard input to standard output.
//
// Building:
// w64dk $ cc -nostartfiles -O -o ipv6fmt.exe ipv6fmt.c -lmemory
// unix  $ cc -O -o ipv6fmt ipv6fmt.c
// test  $ cc -g3 -DTEST -fsanitize=address,undefined ipv6fmt.c
//
// Requires GCC >= 15, or any version of Clang.
//
// Porting: implement os_read(), os_write(), call ipv6fmt().
//
// Ref: https://utcc.utoronto.ca/~cks/space/blog/unix/SortingIPv6Addresses
// Ref: https://www.rfc-editor.org/rfc/rfc4291.html
// Ref: https://www.rfc-editor.org/rfc/rfc5952.html
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>

#define NAME "ipv6fmt"

#define affirm(c)       while (!(c)) __builtin_unreachable()
#define lenof(a)        (iz)(sizeof(a) / sizeof(*(a)))
#define s(s)            (Str){(u8 *)s, lenof(s)-1}
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))

typedef unsigned char   u8;
typedef uint16_t        u16;
typedef int32_t         b32;
typedef int32_t         i32;
typedef ptrdiff_t       iz;
typedef size_t          uz;

static i32 os_read(i32, u8 *, i32);
static b32 os_write(i32, u8 *, i32);

enum {
    IPV6_MAX_LEN = 39,
};

static u8 hex[16] = "0123456789abcdef";

typedef struct {
    u8 *beg;
    u8 *end;
} Arena;

static void *alloc(Arena *a, iz count, iz size, iz align)
{
    iz pad = (iz)-(uz)a->beg & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    u8 *r = a->beg + pad;
    a->beg += pad + count*size;
    return __builtin_memset(r, 0, (uz)(count*size));
}

typedef struct {
    u8 *data;
    iz  len;
} Str;

static Str import(u8 *s)
{
    Str r = {};
    r.data = s;
    for (; r.data[r.len]; r.len++) {}
    return r;
}

static Str clone(Arena *a, Str s)
{
    Str r = s;
    r.data = new(a, s.len, u8);
    affirm(r.len >= 0);
    __builtin_memcpy(r.data, s.data, (uz)r.len);
    return r;
}

static Str span(u8 *beg, u8 *end)
{
    Str r = {};
    r.data = beg;
    r.len  = end - beg;
    return r;
}

static b32 equals(Str a, Str b)
{
    if (a.len != b.len) {
        return 0;
    }
    for (iz i = 0; i < a.len; i++) {
        if (a.data[i] != b.data[i]) {
            return 0;
        }
    }
    return 1;
}

static Str slice(Str s, iz beg, iz end)
{
    affirm(beg <= end);
    affirm(beg>=0 && beg<=s.len);
    affirm(end>=0 && end<=s.len);
    s.data += beg;
    s.len   = end - beg;
    return s;
}

static b32 hasprefix(Str s, Str prefix)
{
    if (s.len < prefix.len) {
        return 0;
    }
    return equals(slice(s, 0, prefix.len), prefix);
}

static b32 hassuffix(Str s, Str suffix)
{
    if (s.len < suffix.len) {
        return 0;
    }
    return equals(slice(s, s.len-suffix.len, s.len), suffix);
}

static Str trimleft(Str s)
{
    u8 *beg = s.data;
    u8 *end = s.data + s.len;
    for (; beg<end && (*beg=='\t' || *beg==' '); beg++) {}
    return span(beg, end);
}

static Str concat(Arena *a, Str head, Str tail)
{
    if (a->beg != head.data+head.len) {
        head = clone(a, head);
    }
    head.len += clone(a, tail).len;
    return head;
}

typedef struct {
    Str head;
    Str tail;
    b32 ok;
} Cut;

static Cut cut(Str s, u8 c)
{
    u8 *beg = s.data;
    u8 *end = s.data + s.len;
    u8 *cut = beg;
    for (; cut<end && *cut!=c; cut++) {}

    Cut r = {};
    r.ok   = cut < end;
    r.head = span(beg, cut);
    r.tail = span(cut+r.ok, end);
    return r;
}

static Cut chop(Str s)
{
    Cut r = {};
    if (hassuffix(s, s("\r\n"))) {
        r.ok   = 1;
        r.head = slice(s, 0, s.len-2);
        r.tail = slice(s, s.len-2, s.len);
        return r;
    } else if (hassuffix(s, s("\n"))) {
        r.ok   = 1;
        r.head = slice(s, 0, s.len-1);
        r.tail = slice(s, s.len-1, s.len);
        return r;
    }
    r.head = s;
    return r;
}

typedef struct {
    u8 a[4];
} Addr4;

typedef struct {
    i32 value;
    b32 ok;
} ParsedOctet;

static ParsedOctet parseoctet(Str s)
{
    ParsedOctet r = {};

    switch (s.len) {
    default: return r;
    case  1: break;
    case  2:
    case  3: if (*s.data=='0') return r;  // leading zero
    }

    for (iz i = 0; i < s.len; i++) {
        u8 c = s.data[i] - '0';
        if (c > 9) {
            return r;
        }
        r.value = r.value*10 + c;
    }

    r.ok = r.value < 256;
    return r;
}

typedef struct {
    Addr4 addr;
    b32   ok;
} ParsedAddr4;

static ParsedAddr4 ipv4parse(Str s)
{
    ParsedAddr4 r = {};
    Cut c = {};
    c.tail = s;
    for (i32 i = 0; i < 4; i++) {
        c = cut(c.tail, '.');
        switch (c.head.len) {
        default:
            return r;
        case 0 ... 3:
            ParsedOctet p = parseoctet(c.head);
            if (!p.ok) {
                return r;
            }
            r.addr.a[i] = (u8)p.value;
        }
    }
    r.ok = !c.ok;
    return r;
}

typedef struct {
    u16 a[8];
} Addr6;

static i32 hexvalue(u8 c)
{
    static u8 t[256] = {
        ['0']= 1, ['1']= 2, ['2']= 3, ['3']= 4, ['4']= 5,
        ['5']= 6, ['6']= 7, ['7']= 8, ['8']= 9, ['9']=10,
        ['A']=11, ['B']=12, ['C']=13, ['D']=14, ['E']=15, ['F']=16,
        ['a']=11, ['b']=12, ['c']=13, ['d']=14, ['e']=15, ['f']=16,
    };
    return t[c] - 1;
}

typedef struct {
    u16 value;
    b32 ok;
} ParsedChunk;

static ParsedChunk parsechunk(Str s)
{
    affirm(s.len>0 && s.len<=4);
    ParsedChunk r = {};
    for (iz i = 0; i < s.len; i++) {
        i32 v = hexvalue(s.data[i]);
        if (v < 0) {
            return r;
        }
        r.value = (u16)(r.value<<4 | v);
    }
    r.ok = 1;
    return r;
}

typedef struct {
    Addr6 addr;
    b32   ok;
} ParsedAddr6;

static ParsedAddr6 ipv6parse(Str s)
{
    ParsedAddr6 r = {};
    i32 len      = 0;
    i32 skip     = -1;

    if (equals(s, s("::"))) {
        r.ok = 1;
        return r;

    } else if (hasprefix(s, s(":"))) {
        if (!hasprefix(s, s("::"))) {
            return r;
        }
        s = slice(s, 1, s.len);

    } else if (hassuffix(s, s(":"))) {
        if (!hassuffix(s, s("::"))) {
            return r;
        }
        s = slice(s, 0, s.len-1);
    }

    Cut c = {};
    c.tail = s;
    c.ok   = s.len > 0;
    while (c.ok) {
        if (len == 8) {
            return r;
        }

        c = cut(c.tail, ':');
        switch (c.head.len) {
        default:
            return r;
        case 0:
            if (skip >= 0) {
                return r;
            }
            skip = len;
            continue;
        case 1 ... 4:
            ParsedChunk p = parsechunk(c.head);
            if (!p.ok) {
                return r;
            }
            r.addr.a[len++] = p.value;
            break;
        case 7 ... 15:
            if (len > 6 || c.ok) {
                return r;
            }
            ParsedAddr4 p4 = ipv4parse(c.head);
            if (!p4.ok) {
                return r;
            }
            r.addr.a[len++] = (u16)(p4.addr.a[0]<<8 | p4.addr.a[1]);
            r.addr.a[len++] = (u16)(p4.addr.a[2]<<8 | p4.addr.a[3]);
            break;
        }
    }

    if (skip >= 0) {
        if (len == 8) {
            return r;
        }
        for (i32 i = 0; i < len-skip; i++) {
            r.addr.a[8-i-1] = r.addr.a[len-i-1];
        }
        for (i32 i = 0; i < 8-len; i++) {
            r.addr.a[i+skip] = 0;
        }
    } else if (len < 8) {
        return r;
    }

    r.ok = 1;
    return r;
}

static Str explode(u8 *dst, Addr6 addr)
{
    Str r = {};
    r.data = dst;
    for (i32 i = 0; i < 8; i++) {
        u16 v = addr.a[i];
        if (i) r.data[r.len++] = ':';
        r.data[r.len++] = hex[(v>>12)     ];
        r.data[r.len++] = hex[(v>> 8) & 15];
        r.data[r.len++] = hex[(v>> 4) & 15];
        r.data[r.len++] = hex[(v    ) & 15];
    }
    return r;
}

static Str compress(u8 *dst, Addr6 addr)
{
    Str r = {};
    r.data = dst;

    // Search for runs of zeros
    i32 best = 0;
    i32 skip = 0;
    i32 run  = 0;
    for (i32 i = 0; i < 8; i++) {
        if (addr.a[i]) {
            run = 0;
        } else {
            run++;
            if (run>2 && run>best) {
                best = run;
                skip = 1 + i - run;
            }
        }
    }

    for (i32 i = 0; i < 8; i++) {
        if (best && i>=skip && i<skip+best) {
            if (i == skip || i == 7) {
                r.data[r.len++] = ':';
            }

        } else {
            if (i) r.data[r.len++] = ':';
            u16 v = addr.a[i];
            switch ((v>0xf) + (v>0xff) + (v>0xfff)) {
            case 3: r.data[r.len++] = hex[(v>>12)   ];  // fallthrough
            case 2: r.data[r.len++] = hex[(v>> 8)&15];  // fallthrough
            case 1: r.data[r.len++] = hex[(v>> 4)&15];  // fallthrough
            case 0: r.data[r.len++] = hex[(v    )&15];
            }
        }
    }

    return r;
}

typedef struct {
    i32 len;
    i32 off;
    b32 eof;
    u8  buf[1<<3];
} Input;

static void refill(Input *b)
{
    affirm(b->len == b->off);
    if (!b->eof) {
        b->len = os_read(0, b->buf, lenof(b->buf));
        if (!b->len) {
            b->eof = 1;
        }
        b->off = 0;
    }
}

static Str nextline(Arena *a, Input *b)
{
    Str r = {};
    while (!b->eof) {
        for (i32 i = b->off; i < b->len; i++) {
            if (b->buf[i] == '\n') {
                Str chunk = span(b->buf+b->off, b->buf+i+1);
                b->off = i + 1;
                if (!r.len) {
                    return chunk;
                }
                return concat(a, r, chunk);
            }
        }

        Str chunk = span(b->buf+b->off, b->buf+b->len);
        r = concat(a, r, chunk);
        b->off = b->len;
        refill(b);
    }
    return r;
}

typedef struct {
    i32 len;
    i32 fd;
    b32 err;
    u8  buf[1<<12];
} Output;

static Output *newoutput(Arena *a, i32 fd)
{
    Output *b = new(a, 1, Output);
    b->fd = fd;
    return b;
}

static void flush(Output *b)
{
    if (!b->err && b->len) {
        b->err = !os_write(b->fd, b->buf, b->len);
        b->len = 0;
    }
}

static void print(Output *b, Str s)
{
    for (iz off = 0; !b->err && off<s.len;) {
        i32 avail = (i32)lenof(b->buf) - b->len;
        i32 count = avail<s.len-off ? avail : (i32)(s.len-off);
        __builtin_memcpy(b->buf+b->len, s.data+off, (uz)count);
        off += count;
        b->len += count;
        if (b->len == lenof(b->buf)) {
            flush(b);
        }
    }
}

static void printu8(Output *b, u8 c)
{
    print(b, (Str){&c, 1});
}

typedef struct {
    Str field;
    Str sep;
    Str tail;
} Field;

// Split fields by the default behavior of POSIX sort in the C locale.
// That is, field separators are the "maximal non-empty sequence of
// <blank> characters that follows a non-<blank>" where blank is space
// and tab.
static Field sortcut(Str s)
{
    u8 *beg = s.data;
    u8 *end = s.data + s.len;
    u8 *cut = beg;
    for (; cut<end && (*cut=='\t' || *cut==' '); cut++) {}
    for (; cut<end && (*cut!='\t' && *cut!=' '); cut++) {}

    Field r = {};
    r.field = span(beg, cut);

    u8 *sep = cut;
    for (; sep<end && (*sep=='\t' || *sep==' '); sep++) {}
    r.sep  = span(cut, sep);
    r.tail = span(sep, end);

    return r;
}

static Field fieldcut(Str s, i32 which, Str sep)
{
    Field r = {};
    if (!which) {
        // No field selected: whole line is the field
        r.field = s;
    } else if (sep.len) {
        // Separator chosen, split on each instance
        Cut c = cut(s, *sep.data);
        r.field = c.head;
        if (c.ok) r.sep = sep;
        r.tail = c.tail;
    } else {
        // Use non-blank-to-blank transitions
        r = sortcut(s);
    }
    return r;
}

typedef struct {
    Str  arg;
    i32  i;
    i32  p;
    u8   option;
    b32  ok;
} Getopt;

static Getopt nextoption(Getopt go, i32 argc, u8 **argv)
{
    go.ok = 0;
    go.i  = !go.i && argc ? 1 : go.i;

    while (go.i < argc) {
        u8 *arg = argv[go.i];

        if (!go.p) {
            if (arg[0] != '-') {
                return go;
            } else if (arg[1]=='-' && arg[2]==0) {
                go.i++;  // consume "--"
                return go;
            }
            go.p = 1;
        }

        go.option = arg[go.p++];
        if (go.option) {
            go.ok = 1;
            return go;
        }
        go.p = 0;
        go.i++;
    }

    return go;
}

static Getopt getarg(Getopt go, i32 argc, u8 **argv)
{
    i32 p = go.p;
    go.p  = 0;
    go.ok = 0;

    if (argv[go.i][p]) {
        go.arg = import(argv[go.i++] + p);
        go.ok  = 1;
        return go;
    }

    if (++go.i == argc) {
        return go;
    }

    go.arg = import(argv[go.i++]);
    go.ok = 1;
    return go;
}

typedef struct {
    i32 value;
    b32 ok;
} Parsed32;

static Parsed32 parsei32(Str s)
{
    Parsed32 r = {};

    for (iz i = 0; i < s.len; i++) {
        u8 c = s.data[i] - '0';
        if (c>9 && r.value > (0x7fffffff-c)/10) {
            return r;
        }
        r.value = r.value*10 + c;
    }

    r.ok = s.len > 0;
    return r;
}

static void usage(Output *b)
{
    print(b, s(
        "usage: " NAME " [OPTIONS] <INPUT >OUTPUT\n"
        "  -c      print addresses in compressed format\n"
        "  -e      print addresses in exploded format\n"
        "  -h      print this message\n"
        "  -k N    process only field N (default: whole line is field)\n"
        "  -t SEP  use specific byte as field separator\n"
    ));
}

static i32 ipv6fmt(Arena a, i32 argc, u8 **argv)
{
    enum { MODE_EXLODE, MODE_COMPRESS };

    Input  *bi = new(&a, 1, Input);
    Output *bo = newoutput(&a, 1);
    Output *be = newoutput(&a, 2);

    i32 mode  = MODE_EXLODE;
    Str sep   = {};
    i32 which = 0;

    Getopt go = {};
    while ((go = nextoption(go, argc, argv)).ok) {
        switch (go.option) {
        case 'c':
            mode = MODE_COMPRESS;
            break;

        case 'e':
            mode = MODE_EXLODE;
            break;

        case 'h':
            usage(bo);
            flush(bo);
            return bo->err;

        case 'k':
            go = getarg(go, argc, argv);
            if (!go.ok) {
                print(be, s(NAME ": -k: missing argument\n"));
                flush(be);
                return 1;
            }
            Parsed32 p = parsei32(go.arg);
            if (!p.ok || !p.value) {
                print(be, s(NAME ": -k: invalid argument\n"));
                flush(be);
                return 1;
            }
            which = p.value;
            break;

        case 't':
            go = getarg(go, argc, argv);
            if (!go.ok) {
                print(be, s(NAME ": -t: missing argument\n"));
                flush(be);
                return 1;
            }
            if (go.arg.len != 1) {
                print(be, s(NAME ": -t: separator not a single byte\n"));
                flush(be);
                return 1;
            }
            sep = go.arg;
            break;

        default:
            print(be, s(NAME ": unknown option: -"));
            printu8(be, go.option);
            print(be, s("\n"));
            usage(be);
            flush(be);
            return 1;
        }
    }

    if (go.i != argc) {
        print(be, s(NAME ": positional arguments unsupported\n"));
        usage(be);
        flush(be);
        return 1;
    }

    for (;;) {
        u8 buf[IPV6_MAX_LEN];
        Arena scratch = a;
        Str line = nextline(&scratch, bi);
        if (!line.len) break;  // EOF
        Cut lineparts = chop(line);

        Field c = {};
        c.tail = lineparts.head;
        for (iz i = 1;; i++) {
            c = fieldcut(c.tail, which, sep);
            if (!c.field.len) break;

            ParsedAddr6 p;
            if ((!which || i == which) && (p = ipv6parse(c.field)).ok) {
                switch (mode) {
                case MODE_EXLODE:
                    print(bo, explode(buf, p.addr));
                    break;
                case MODE_COMPRESS:
                    print(bo, compress(buf, p.addr));
                    break;
                }
            } else {
                print(bo, c.field);
            }

            print(bo, c.sep);
        }

        print(bo, lineparts.tail);
    }

    flush(bo);
    return bo->err;
}


#if TEST
#include <stdio.h>

static i32 os_read(i32, u8 *, i32) { affirm(0); }
static b32 os_write(i32, u8 *, i32) { affirm(0); }

static b32 addrequals(Addr6 a, Addr6 b)
{
    return !__builtin_memcmp(a.a, b.a, sizeof(a.a));
}

void test_parse()
{
    static struct {
        b32   ok;
        Str   input;
        Addr6 addr;
    } t[] = {
        {
            1, s("2001:0db8:0000:0000:0000:ff00:0042:8329"),
            {{0x2001, 0x0db8, 0, 0, 0, 0xff00, 0x42, 0x8329}},
        },
        {
            1, s("2001:db8:0:0:0:ff00:42:8329"),
            {{0x2001, 0x0db8, 0, 0, 0, 0xff00, 0x42, 0x8329}},
        },
        {
            1, s("2001:db8::ff00:42:8329"),
            {{0x2001, 0x0db8, 0, 0, 0, 0xff00, 0x42, 0x8329}},
        },
        { 0, s("2001:00db8::ff00:42:8329"), {}, },
        { 1, s("::2:1"), {{0, 0, 0, 0, 0, 0, 0x2, 0x1}}, },
        { 1, s("1:2::"), {{0x1, 0x2, 0, 0, 0, 0, 0, 0}}, },
        { 1, s("1::"), {{0x1, 0, 0, 0, 0, 0, 0, 0}}, },
        { 1, s("::1"), {{0, 0, 0, 0, 0, 0, 0, 0x1}}, },
        { 1, s("fffe::1"), {{0xfffe, 0, 0, 0, 0, 0, 0, 0x1}}, },
        { 1, s("::"), {}, },
        { 0, s(":::"), {}, },
        { 0, s(":1"), {}, },
        { 0, s("1:"), {}, },
        { 0, s("0:0"), {}, },
        { 0, s(":"), {}, },
        { 0, s(""), {}, },
        { 0, s("0:0:0:0:0:0:0:0:0"), {}, },
        { 0, s("0:0:0:0:0:0:0:0:"), {}, },
        { 0, s("::-1"), {}, },
        { 1, s("::1.2.3.4"), {{0, 0, 0, 0, 0, 0, 0x0102, 0x0304}}, },
        { 1, s("::0.0.0.0"), {}, },
        { 0, s("::1.2.3.4:5"), {}, },
        { 0, s("1.2.3.4::"), {}, },
        { 0, s("::1.256.3.4"), {}, },
        { 0, s("::1.02.3.4"), {}, },
    };

    for (i32 i = 0; i < lenof(t); i++) {
        ParsedAddr6 p = ipv6parse(t[i].input);
        affirm(p.ok == t[i].ok);
        if (p.ok) {
            affirm(addrequals(p.addr, t[i].addr));
        }
    }
}

void test_compress()
{
    Str t[] = {
        s("::"),
        s("::1"),
        s("1::"),
        s("0:1::"),
        s("0:1::2:0"),
        s("0:1::2:0:0"),
        s("0:1:0:2::"),
    };

    for (i32 i = 0; i < lenof(t); i++) {
        Str s = compress((u8[IPV6_MAX_LEN]){}, ipv6parse(t[i]).addr);
        affirm(equals(s, t[i]));
    }
}

int main()
{
    test_parse();
    test_compress();
}


#elif _WIN32
typedef u16         char16_t;
typedef char16_t    c16;

enum {
    CP_UTF8                 = 65001,
};

#define W32 __attribute((dllimport, stdcall))
W32 c16   **CommandLineToArgvW(c16 *, i32 *);
W32 void    ExitProcess(i32) __attribute((noreturn));
W32 c16    *GetCommandLineW();
W32 uz      GetStdHandle(i32);
W32 i32     WideCharToMultiByte(i32, i32, c16 *, i32, u8 *, i32, uz, uz);
W32 b32     ReadFile(uz, u8 *, i32, i32 *, uz);
W32 b32     WriteFile(uz, u8 *, i32, i32 *, uz);

static i32 os_read(i32 fd, u8 *buf, i32 len)
{
    uz h = GetStdHandle(-10 - fd);
    ReadFile(h, buf, len, &len, 0);
    return len;
}

static b32 os_write(i32 fd, u8 *buf, i32 len)
{
    uz h = GetStdHandle(-10 - fd);
    return WriteFile(h, buf, len, &len, 0);
}

i32 mainCRTStartup()
{
    static u8 mem[1<<24];
    Arena a = {mem, mem+lenof(mem)};

    c16  *cmd   = GetCommandLineW();
    i32   argc  = 0;
    c16 **wargv = CommandLineToArgvW(cmd, &argc);
    u8  **argv  = new(&a, argc+1, u8 *);
    for (i32 i = 0; i < argc; i++) {
        i32 len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, 0, 0, 0, 0);
        argv[i] = new(&a, len, u8);
        WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, argv[i], len, 0, 0);
    }

    return ipv6fmt(a, argc, argv);
}


#else
#include <unistd.h>

static i32 os_read(i32 fd, u8 *buf, i32 len)
{
    return read(fd, buf, len);
}

static b32 os_write(i32 fd, u8 *buf, i32 len)
{
    return write(fd, buf, len) == len;
}

int main(int argc, char **argv)
{
    static u8 mem[1<<24];
    Arena a = {mem, mem+lenof(mem)};
    return ipv6fmt(a, argc, (u8 **)argv);
}
#endif
