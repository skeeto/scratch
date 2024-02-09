// Fast file space usage tool for Windows
// $ cc -nostartfiles -O -o du.exe du.c
// Features:
// * Runs ~10x faster than other du ports (msys2, busybox)
// * Full support for wide paths, long paths, and wide console printing
// This is free and unencumbered software released into the public domain.

#define assert(c)     while (!(c)) __builtin_unreachable()
#define countof(a)    (size)(sizeof(a) / sizeof(*(a)))
#define new(a, t, n)  (t *)alloc(a, sizeof(t), __alignof(t), n)
#define s(s)          (s16){u##s, countof(s)-1}

typedef unsigned char      u8;
typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef   signed long long i64;
typedef unsigned long long u64;
typedef unsigned short     char16_t;
typedef          char16_t  c16;
typedef   signed int       char32_t;
typedef          char32_t  c32;
typedef          char      byte;
typedef __PTRDIFF_TYPE__   size;
typedef __INTPTR_TYPE__    iptr;
typedef __UINTPTR_TYPE__   uptr;

typedef struct {
    i32 attr;
    u32 create[2];
    u32 access[2];
    u32 modify[2];
    u32 size[2];
    i32 _[2];
    c16 name[260];
    c16 altname[14];
} FindDataW;

typedef struct {
    i32 attr;
    u32 create[2];
    u32 access[2];
    u32 modify[2];
    u32 serial;
    u32 size[2];
    u32 nlinks;
    u32 index[2];
} FileInfo;

#define W32 __attribute((dllimport, stdcall))
W32 b32   CloseHandle(iptr);
W32 c16 **CommandLineToArgvW(c16 *, i32 *);  // shell32.dll
W32 iptr  CreateFileW(c16 *, i32, i32, uptr, i32, i32, uptr);
W32 void  ExitProcess(i32);
W32 b32   FindClose(iptr);
W32 iptr  FindFirstFileW(c16 *, FindDataW *);
W32 b32   FindNextFileW(iptr, FindDataW *);
W32 c16  *GetCommandLineW(void);
W32 b32   GetConsoleMode(iptr, i32 *);
W32 b32   GetFileInformationByHandle(iptr, FileInfo *);
W32 iptr  GetStdHandle(i32);
W32 byte *VirtualAlloc(uptr, size, i32, i32);
W32 b32   WriteConsoleW(iptr, c16 *, i32, i32 *, uptr);
W32 b32   WriteFile(iptr, u8 *, i32, i32 *, uptr);

typedef struct {
    byte *beg;
    byte *end;
    uptr *oom;
} arena;

__attribute((malloc, alloc_size(2, 3)))
static byte *alloc(arena *a, size objsize, size align, size count)
{
    size padding = (uptr)a->end & (align - 1);
    if (count > (a->end - a->beg - padding)/objsize) {
        __builtin_longjmp(a->oom, 1);
    }
    size total = objsize * count;
    return __builtin_memset(a->end -= total + padding, 0, total);
}

static void c16copy(c16 *dst, c16 *src, size len)
{
    assert(dst);
    assert(src);
    assert(len >= 0);
    __builtin_memcpy(dst, src, sizeof(c16)*len);
}

static b32 highsurrogate(c16 c)
{
    return c>=0xd800 && c<=0xdbff;
}

typedef struct {
    c16 *data;
    size len;
} s16;

static s16 s16span(c16 *beg, c16 *end)
{
    assert(beg);
    assert(end);
    s16 r  = {0};
    r.data = beg;
    r.len  = end - beg;
    return r;
}

static s16 s16clone(arena *perm, s16 s)
{
    s16 r = s;
    r.data = new(perm, c16, s.len);
    c16copy(r.data, s.data, s.len);
    return r;
}

static s16 s16import(c16 *s)
{
    s16 r = {0};
    r.data = s;
    for (; s[r.len]; r.len++) {}
    return r;
}

static c16 *s16export(s16 s, arena *perm)
{
    c16 *c = new(perm, c16, s.len+1);
    c16copy(c, s.data, s.len);
    return c;
}

static b32 s16equals(s16 a, s16 b)
{
    return a.len==b.len && !__builtin_memcmp(a.data, b.data, a.len);
}

static s16 s16cuthead(s16 s, size len)
{
    assert(len >= 0);
    assert(len <= s.len);
    s.data += len;
    s.len -= len;
    return s;
}

typedef struct {
    s16 tail;
    c32 rune;
} utf16;

static utf16 utf16decode(s16 s)
{
    assert(s.len);
    utf16 r = {0};
    r.rune = s.data[0];
    if (r.rune>=0xdc00 && r.rune<=0xdfff) {
        goto reject;  // unpaired low surrogate
    } else if (r.rune>=0xd800 && r.rune<=0xdbff) {
        if (s.len < 2) {
            goto reject;  // missing low surrogate
        }
        i32 hi = r.rune;
        i32 lo = s.data[1];
        if (lo<0xdc00 || lo>0xdfff) {
            goto reject;  // expected low surrogate
        }
        r.rune = 0x10000 + ((hi - 0xd800)<<10) + (lo - 0xdc00);
        r.tail = s16cuthead(s, 2);
        return r;
    }
    r.tail = s16cuthead(s, 1);
    return r;

    reject:
    r.rune = 0xfffd;
    r.tail = s16cuthead(s, 1);
    return r;
}

static i32 utf8encode(u8 *s, c32 rune)
{
    switch ((rune >= 0x80) + (rune >= 0x800) + (rune >= 0x10000)) {
    case 0: s[0] = (u8)(0x00 | ((rune >>  0)     )); return 1;
    case 1: s[0] = (u8)(0xc0 | ((rune >>  6)     ));
            s[1] = (u8)(0x80 | ((rune >>  0) & 63)); return 2;
    case 2: s[0] = (u8)(0xe0 | ((rune >> 12)     ));
            s[1] = (u8)(0x80 | ((rune >>  6) & 63));
            s[2] = (u8)(0x80 | ((rune >>  0) & 63)); return 3;
    case 3: s[0] = (u8)(0xf0 | ((rune >> 18)     ));
            s[1] = (u8)(0x80 | ((rune >> 12) & 63));
            s[2] = (u8)(0x80 | ((rune >>  6) & 63));
            s[3] = (u8)(0x80 | ((rune >>  0) & 63)); return 4;
    }
    assert(0);
}

enum { out_UTF8, out_WIDE };

typedef struct {
    iptr handle;
    union {
        u8  *utf8;
        c16 *wide;
    };
    i32  cap;
    i32  len;
    i32  kind;
    b32  err;
} bufout;

static bufout *newbufout(arena *perm, i32 fd, i32 cap)
{
    bufout *b = new(perm, bufout, 1);
    b->handle = GetStdHandle(-10 - fd);
    if (GetConsoleMode(b->handle, &b->kind)) {
        b->kind = out_WIDE;
        b->wide = new(perm, c16, cap);
    } else {
        b->kind = out_UTF8;
        b->utf8 = new(perm, u8, cap);
    }
    b->cap = cap;
    return b;
}

static void flush(bufout *b)
{
    if (!b->err && b->len) {
        switch (b->kind) {
        case out_UTF8:
            b->err = !WriteFile(b->handle, b->utf8, b->len, &b->len, 0);
            break;
        case out_WIDE:
            b->err = !WriteConsoleW(b->handle, b->wide, b->len, &b->len, 0);
            break;
        }
    }
    b->len = 0;
}

static void softflush(bufout *b)
{
    switch (b->kind) {
    case out_UTF8:
        break;
    case out_WIDE:
        c16 last = b->len ? b->wide[b->len-1] : 0;
        if (highsurrogate(last)) {
            // Do not straddle surrogate pairs across writes
            b->len--;
            flush(b);
            b->wide[0] = last;
            b->len = 1;
            return;
        }
    }
    flush(b);
}

static void prints16(bufout *b, s16 s)
{
    switch (b->kind) {
    case out_UTF8:
        utf16 u = {0};
        u.tail = s;
        while (!b->err && u.tail.len) {
            if (b->cap - b->len < 4) {
                flush(b);
            }
            u = utf16decode(u.tail);
            b->len += utf8encode(b->utf8+b->len, u.rune);
        }
        break;
    case out_WIDE:
        for (size off = 0; !b->err && off<s.len;) {
            i32 avail = b->cap - b->len;
            i32 count = s.len-off<avail ? (i32)(s.len-off) : avail;
            c16copy(b->wide+b->len, s.data+off, count);
            off += count;
            b->len += count;
            if (b->len == b->cap) {
                softflush(b);
            }
        }
        break;
    }
}

static void printi64(bufout *b, i64 x)
{
    c16  buf[32];
    c16 *end = buf + countof(buf);
    c16 *beg = end;
    i64 t = x<0 ? x : -x;
    do {
        *--beg = '0' - (c16)(t%10);
    } while (t /= 10);
    beg[-1] = '-';
    beg -= x < 0;
    prints16(b, s16span(beg, end));
}

// Print a human-friendly size in IEC units with 1 decimal place. Plain
// bytes have no unit suffix.
static void printunits(bufout *b, i64 x)
{
    if (x < 1024) {
        printi64(b, x);
        return;
    }

    i32 units = 0;
    x *= 10;  // fixed point, 1 decimal place
    x = (x + 512)>>10;
    for (; x>10000 && units<4; units++) {
        x = (x + 512)>>10;
    }
    printi64(b, x/10);
    c16 decimal[3] = {0};
    decimal[0] = '.';
    decimal[1] = (c16)(x%10) + '0';
    decimal[2] = "KMGTP"[units];
    prints16(b, s16span(decimal, decimal+countof(decimal)));
}

typedef struct node node;
struct node {
    node *next;
    node *parent;
    s16   name;
};

typedef struct {
    node  *head;
    node **tail;
} queue;

static void push(queue *q, node *parent, s16 name, arena *perm)
{
    node *n = new(perm, node, 1);
    n->name = name;
    n->parent = parent;
    if (q->head) {
        *q->tail = n;
    } else {
        q->head = n;
    }
    q->tail = &n->next;
}

static node *pop(queue *q)
{
    assert(q->head);
    node *r = q->head;
    q->head = r->next;
    r->next = 0;
    return r;
}

// A UTF-16 buffer that grows back to front, only prepending.
typedef struct {
    s16    path;
    arena *perm;
} pathbuf;

// Grow a path into of the unused portion of the arena.
static pathbuf newpathbuf(arena *perm)
{
    pathbuf b = {0};
    b.path.data = (c16 *)perm->end;
    b.perm = perm;
    return b;
}

// The path grows in place inside the arena. Do not prepend after new().
static void prepend(pathbuf *b, s16 s)
{
    c16 *beg = new(b->perm, c16, s.len);
    b->path.data -= s.len;
    assert(beg == b->path.data);
    b->path.len += s.len;
    c16copy(b->path.data, s.data, s.len);
}

// Build a path string for FindFirstFileW.
static s16 topath(node *last, s16 suffix, arena *perm)
{
    pathbuf b = newpathbuf(perm);
    prepend(&b, s("\0"));
    prepend(&b, suffix);
    for (; last; last = last->parent) {
        prepend(&b, s("\\"));
        prepend(&b, last->name);
    }
    return b.path;
}

// Convert all slashes to backslashes (for tidy errors).
static s16 normalize(s16 s, arena *perm)
{
    s = s16clone(perm, s);
    for (size i = 0; i < s.len; i++) {
        s.data[i] = s.data[i]=='/' ? '\\' : s.data[i];
    }
    return s;
}

// Paths cannot contain '?' nor '*' but FindFirstFileW interprets them,
// so check before using it.
static b32 invalid(s16 path)
{
    for (size i = 0; i < path.len; i++) {
        switch (path.data[i]) {
        case '*':
        case '?': return 0;
        }
    }
    return !path.len;
}

static b32 ispathsep(c16 c)
{
    return c=='/' || c=='\\';
}

static s16 trimpath(s16 path)
{
    for (; path.len && ispathsep(path.data[path.len-1]); path.len--) {}
    return path;
}

static b32 isdir(FindDataW *fd)
{
    return fd->attr & 0x10;
}

enum { ERR=-1, DIR=-2 };

static i64 getfilesize(s16 path, arena scratch)
{
    c16 *cpath = s16export(path, &scratch);
    FindDataW *fd = new(&scratch, FindDataW, 1);
    iptr h = FindFirstFileW(cpath, fd);
    if (h == -1) return ERR;
    FindClose(h);
    if (isdir(fd)) return DIR;
    return (i64)fd->size[0]<<32 | fd->size[1];
}

typedef struct {
    u64 v[2];
} fileid;

static b32 nullid(fileid id)
{
    return !id.v[0];
}

// Get the system-unique file ID for the named file. Zero on error. This
// is slow and calls should be avoided.
static fileid getfileid(node *dir, s16 name, arena scratch)
{
    s16 path = topath(dir, name, &scratch);
    fileid r = {0};
    iptr h = CreateFileW(path.data, 0x80000000, 7, 0, 3, 0x80, 0);
    if (h == -1) {
        return r;
    }
    FileInfo info;
    if (GetFileInformationByHandle(h, &info) && info.nlinks>1) {
        r.v[0] = (u64)1<<33 | info.serial;
        r.v[1] = (u64)info.index[0]<<32 | info.index[1];
    }
    CloseHandle(h);
    return r;
}

static u64 hashid(fileid id)
{
    u64 h = 0;
    h ^= id.v[0]; h *= 1111111111111111111u;
    h ^= id.v[1]; h *= 1111111111111111111u;
    return h;
}

static u64 idequals(fileid a, fileid b)
{
    return a.v[0]==b.v[0] && a.v[1]==b.v[1];
}

typedef struct idset idset;
struct idset {
    idset *child[2];  // prioritize memory
    fileid id;
};

static b32 insertid(idset **m, fileid id, arena *perm)
{
    for (u64 h = hashid(id); *m; h <<= 1) {
        if (idequals((*m)->id, id)) {
            return 0;
        }
        m = &(*m)->child[h>>63];
    }
    *m = new(perm, idset, 1);
    (*m)->id = id;
    return 1;
}

static u64 hashinfo(FindDataW *fd)
{
    u64 h = 0;
    h ^= fd->create[0] | (u64)fd->create[1]<<32;
    h *= 1111111111111111111u;
    #if 0  // NOTE: differs between hard links!
    h ^= fd->access[0] | (u64)fd->access[1]<<32;
    h *= 1111111111111111111u;
    #endif
    h ^= fd->modify[0] | (u64)fd->modify[1]<<32;
    h *= 1111111111111111111u;
    h ^= fd->size[0]   | (u64)fd->size[1]  <<32;
    h *= 1111111111111111111u;
    return h;
}

typedef struct infoset infoset;
struct infoset {
    infoset *child[4];  // prioritize speed
    u64      key;       // hashinfo() result
    node    *dir;
    s16      name;
};

// Tracks all seen files for potential hard links.
typedef struct {
    infoset *infos;  // probabilistic filter hash set
    idset   *ids;    // actually-observed hard links
} linkdb;

static b32 ishardlink(linkdb *db, u64 key, node *dir, s16 name, arena *perm)
{
    // Search the probabilistic filter for a tentative match using only
    // FindDataW metadata. Hard links have matching metadata, but may
    // have false positives. Only the hash is stored and compared. The
    // point is to avoid calling CreateFileW, which is *very* slow.
    b32 found = 0;
    infoset **infos = &db->infos;
    for (u64 h = key; *infos; h <<= 2) {
        if ((*infos)->key == key) {
            found = 1;
            break;
        }
        infos = &(*infos)->child[h>>62];
    }

    if (!found) {
        // Unique metadata, not hard linked with previous file. Store
        // the path and name in order to retrieve the file ID later.
        *infos = new(perm, infoset, 1);
        (*infos)->key  = key;
        (*infos)->dir  = dir;
        (*infos)->name = s16clone(perm, name);
        return 0;
    }

    idset **ids = &db->ids;
    if ((*infos)->dir) {
        // First time this tentative hard link has been seen. Retrieve
        // the ID and then insert it in the exact hashset as though it
        // had been there the entire time.
        fileid id = getfileid((*infos)->dir, (*infos)->name, *perm);
        (*infos)->dir = 0;  // mark as inserted
        if (!nullid(id)) {
            b32 r = insertid(ids, id, perm);
            assert(r);  // trips if hashinfo() is broken
        }
    }

    // Slow ID retrieval for exact hashset lookup
    fileid id = getfileid(dir, name, *perm);
    if (nullid(id) || insertid(ids, id, perm)) {
        return 0;
    }
    return 1;
}

static void erropen(bufout *err, s16 path)
{
    prints16(err, s("du: could not open "));
    prints16(err, path);
    prints16(err, s("\n"));
    flush(err);
}

typedef struct {
    b32 quiet;
    b32 count_links;
    b32 print_memstat;
} config;

typedef struct {
    i64  total;
    size memory;
    b32  err;
} filesize;

static filesize gettotal(s16 path, config *conf, arena scratch, bufout *err)
{
    filesize r = {0};
    r.memory = scratch.end - scratch.beg;

    path = trimpath(path);
    if (invalid(path)) {
        prints16(err, s("du: invalid path: "));
        prints16(err, path);
        prints16(err, s("\n"));
        flush(err);
        r.total = -1;
        r.err = 1;
        return r;
    }

    // Is it just a file?
    r.total = getfilesize(path, scratch);
    switch (r.total) {
    default:  return r;
    case ERR: erropen(err, path);
              r.total = -1;
              r.err = 1;
              return r;
    case DIR: break;
    }

    FindDataW *fd = new(&scratch, FindDataW, 1);
    linkdb *db = conf->count_links ? 0 : new(&scratch, linkdb, 1);

    // BFS requires more memory than DFS. While this program doesn't
    // fully exploit it (e.g. easy parallel traversal), the hash sets
    // share structure with the queue, so they complement each other.
    // Besides this, the BFS itself uses very little memory even with
    // huge file trees.
    queue *q = new(&scratch, queue, 1);
    push(q, 0, path, &scratch);

    while (q->head) {
        node *dir = pop(q);

        // NOTE: The OOM handler could be moved into this function,
        // allowing it to close this Find handle on OOM, then return
        // with an error. However, OOM is a quick exit anyway, so it
        // doesn't practically matter.
        iptr h = 0;
        {
            arena temp = scratch;
            s16 path = topath(dir, s("*"), &temp);
            h = FindFirstFileW(path.data, fd);
            if (h == -1) {
                path.len -= 3;  // chop the glob
                if (!conf->quiet) {
                    erropen(err, normalize(path, &temp));
                }
                r.err |= 1;
                continue;
            }
        }

        do {
            // NOTE: Everything could be accomplished with ASCII 8.3 DOS
            // names (altname), saving memory when storing components in
            // the queue. For error messages, use GetLongPathNameW at
            // the last moment to expand it to a friendly name, so the
            // DOS names remain invisible to users. But maybe this would
            // slow Find{First,Next}FileW? Something to investigate.
            s16 name = s16import(fd->name);
            if (s16equals(s("."), name) || s16equals(s(".."), name)) {
                continue;
            } else if (isdir(fd)) {
                name = s16clone(&scratch, name);
                push(q, dir, name, &scratch);
            } else {
                u64 key = hashinfo(fd);
                if (!db || !ishardlink(db, key, dir, name, &scratch)) {
                    r.total += (i64)fd->size[0]<<32 | fd->size[1];
                }
            }
        } while (FindNextFileW(h, fd));

        FindClose(h);
    }

    r.memory -= scratch.end - scratch.beg;
    return r;
}

typedef struct {
    c16 *optarg;
    i32  optind;
    i32  optopt;
    i32  optpos;
} wgo;

static i32 wgetopt(wgo *x, i32 argc, c16 **argv, u8 *optstring)
{
    x->optind += !x->optind;
    c16 *arg = x->optind<argc ? argv[x->optind] : 0;
    if (arg && arg[0] == '-' && arg[1] == '-' && !arg[2]) {
        x->optind++;
        return -1;
    } else if (!arg || arg[0] != '-' || ((arg[1] < '0' || arg[1] > '9') &&
                                         (arg[1] < 'A' || arg[1] > 'Z') &&
                                         (arg[1] < 'a' || arg[1] > 'z'))) {
        return -1;
    } else {
        while (*optstring && arg[x->optpos+1] != *optstring) {
            optstring++;
        }
        x->optopt = arg[x->optpos+1];
        if (!*optstring) {
            return '?';
        } else if (optstring[1] == ':') {
            if (arg[x->optpos+2]) {
                x->optarg = arg + x->optpos + 2;
                x->optind++;
                x->optpos = 0;
                return x->optopt;
            } else if (x->optind+1 < argc) {
                x->optarg = argv[x->optind+1];
                x->optind += 2;
                x->optpos = 0;
                return x->optopt;
            } else {
                return ':';
            }
        } else {
            if (!arg[++x->optpos+1]) {
                x->optind++;
                x->optpos = 0;
            }
            return x->optopt;
        }
    }
}

static void usage(bufout *b)
{
    static const c16 usage[] =
    u"du: [-hlqv] <PATH...>\n"
    u"  -h     print this message\n"
    u"  -l     accumulate hard link sizes\n"
    u"  -q     do not print file access errors\n"
    u"  -v     print memory statistics (debugging)\n";
    s16 s = {0};
    s.data = (c16 *)usage;
    s.len = countof(usage) - 1;
    prints16(b, s);
    flush(b);
}

static i32 run(arena scratch)
{

    bufout *stdout = newbufout(&scratch, 1, 1<<12);
    bufout *stderr = newbufout(&scratch, 2, 1<<8);

    uptr oom[5] = {0};
    if (__builtin_setjmp(oom)) {
        prints16(stderr, s("out of memory\n"));
        flush(stderr);
        return 1;
    }
    scratch.oom = oom;

    c16 *cmd = GetCommandLineW();
    i32 argc;
    c16 **argv = CommandLineToArgvW(cmd, &argc);

    // TODO: command line switches -a -c -dN -H -L
    config *conf = new(&scratch, config, 1);
    wgo g = {0};
    for (i32 opt; (opt = wgetopt(&g, argc, argv, (u8 *)"hlqv")) != -1;) {
        switch (opt) {
        case 'h': usage(stdout);
                  return stdout->err;
        case 'l': conf->count_links = 1;
                  break;
        case 'q': conf->quiet = 1;
                  break;
        case 'v': conf->print_memstat = 1;
                  break;
        case ':':
        case '?': usage(stderr);
                  return 1;
        }
    }

    b32 err = 0;
    for (i32 i = g.optind; i < argc; i++) {
        s16 path = s16import(argv[i]);
        filesize f = gettotal(path, conf, scratch, stderr);
        err |= f.err;
        if (f.total < 0) continue;
        printunits(stdout, f.total);
        prints16(stdout, s("\t"));
        if (conf->print_memstat) {
            printunits(stdout, f.memory);
            prints16(stdout, s("\t"));
        }
        prints16(stdout, path);
        prints16(stdout, s("\n"));
    }

    flush(stdout);
    err |= stdout->err;
    return err;
}

void mainCRTStartup(void)
{
    size cap = 1<<28;
    arena scratch = {0};
    scratch.beg = VirtualAlloc(0, cap, 0x3000, 4);
    scratch.end = scratch.beg + cap;
    i32 r = run(scratch);
    ExitProcess(r);
    assert(0);
}
