// cloc: Count Lines of Code
//   $ gcc -nostartfiles -o cloc.exe cloc.c
//   $ cloc -qn10 src/ lib/
// TODO: abstract "Char16" paths into opaque objects, or UTF-8
// TODO: then write a Linux platform layer
// This is free and unencumbered software released into the public domain.


// Basic definitions

typedef int Bool;
typedef unsigned char Byte;
typedef __UINT16_TYPE__ Char16;
typedef __INT32_TYPE__ Int32;
typedef __UINT32_TYPE__ Uint32;
typedef __INT64_TYPE__ Int64;
typedef __UINT64_TYPE__ Uint64;
typedef __PTRDIFF_TYPE__ Size;
typedef __SIZE_TYPE__ Usize;
#define Size_MAX (Size)((Usize)-1 >> 1)

#if __amd64 || __i686
  #define PAUSE __builtin_ia32_pause()
#else
  #define PAUSE
#endif

#ifdef DEBUG
  #define ASSERT(c) if (!(c)) __builtin_trap()
#else
  #define ASSERT(c) (void)sizeof(c)
#endif


// Platform API

#define Path_MAX 260

typedef struct {
    Byte *buf;
    Size len;
} PlatformMap;

typedef struct {
    void *handle;
    Char16 name[Path_MAX];
    Bool dir;
    Bool first;
} PlatformDir;

typedef struct {
    // Heap
    void *heap;
    Size heapsize;

    // Write to standard output (1) or error (2)
    Bool (*write)(int, void *, Size);

    // File loading
    Bool (*map)(PlatformMap *, Char16 *);
    void (*unmap)(PlatformMap *);

    // Directory listing
    Bool (*diropen)(PlatformDir *, Char16 *);
    Bool (*dirnext)(PlatformDir *);

    // Futex (optional: may be no-op)
    void (*wait)(unsigned *, unsigned);
    void (*wake)(unsigned *);
    void (*wakeall)(unsigned *);

    // Debug log (null-terminated, may be no-op)
    void (*debug)(Byte *);
} Platform;


// Application API

// Initialize the application, establishing a context object. Returns a
// null pointer if initialization fails. Otherwise the platform will
// spin up an appropriate number of threads, possibly zero, passing this
// context pointer to each thread.
static void *clocinit(Platform *, int argc, Char16 **argv);

// Worker thread entry point. The platform passes the non-null pointer
// returned by clocinit().
static void clocthread(void *context);

// Main application entry point, passed the non-null pointer returned by
// the clocinit(). The return value is the exit status.
static int clocmain(void *context);


// Application

#define SIZEOF(e) (Size)(sizeof(e))
#define NEW(a, t) (t *)alloc(a, SIZEOF(t))
#define ARRAY(a, t, n) (t *)alloc(a, SIZEOF(t)*(n))
#define SAVEPOINT(a) __builtin_setjmp((a)->jmp)
#define OUTSTR(o, s) outbytes(o, (Byte *)s, SIZEOF(s)-1)
#define ZERO(x) zero(x, SIZEOF(*x))

__attribute__((optimize("no-tree-loop-distribute-patterns")))
static void zero(void *p, Size size)
{
    Byte *b = p;
    for (Size i = 0; i < size; i++) {
        b[i] = 0;
    }
}

typedef struct {
    Size cap;
    Size off;
    void *jmp[5];
} Arena;

static Arena *placearena(void *mem, Size size)
{
    ASSERT(size >= SIZEOF(Arena));
    Arena *a = mem;
    ZERO(a);
    a->cap = size;
    a->off = SIZEOF(Arena);
    return a;
}

__attribute__((malloc,alloc_size(2)))
static void *alloc(Arena *a, Size size)
{
    ASSERT(size >= 0);
    Size avail = a->cap - a->off;
    if (avail < size) {
        __builtin_longjmp(a->jmp, 1);
    }
    Byte *p = (Byte *)a + a->off;
    zero(p, size);
    a->off += size;
    return p;
}

typedef struct {
    int tickets;
    int current;
} Mutex;

static void lock(Mutex *m)
{
    int ticket = __atomic_fetch_add(&m->tickets, 1, __ATOMIC_RELAXED);
    for (;;) {
        int current = __atomic_load_n(&m->current, __ATOMIC_ACQUIRE);
        if (ticket == current) {
            break;
        }
        PAUSE;
    }
}

static void unlock(Mutex *m)
{
    __atomic_fetch_add(&m->current, 1, __ATOMIC_RELEASE);
}

typedef struct Path {
    struct Path *next;
    Int64 files;
    Int64 lines;
    Int64 blanks;
    Char16 path[Path_MAX];
} Path;

static int pathcmp(Path *x, Path *y)
{
    if (x->lines != y->lines) {
        return x->lines > y->lines ? -1 : +1;
    } else if (x->files != y->files) {
        return x->files > y->files ? -1 : +1;
    } else {
        for (int i = 0;; i++) {
            if (x->path[i] != y->path[i]) {
                return x->path[i]<y->path[i] ? -1 : +1;
            }
        }
    }
    // NOTE: Equivalent paths should have been merged.
    ASSERT(0);
    __builtin_unreachable();
}

static int pathlen(Path *p)
{
    int len = 0;
    for (; p->path[len]; len++) {}
    return len;
}

static Bool tally(Platform *plt, Path *path)
{
    PlatformMap map;
    if (!plt->map(&map, path->path)) {
        return 0;
    }

    // Truncate path to just its extension
    int ext = 0;
    for (; path->path[ext]; ext++) {}
    for (; ext; ext--) {
        switch (path->path[ext-1]) {
        default  : continue;
        case '.' : break;
        case '/' :
        case '\\': ext = 0;
        }
        break;
    }
    if (ext) {
        for (int i = 0; path->path[i]; i++) {
            path->path[i] = path->path[ext+i];
        }
    } else {
        path->path[0] = 0;
    }

    Bool blank = 1;
    Size line = 0;
    for (Size i = 0; i < map.len; i++) {
        switch (map.buf[i]) {
        case ' ' :
        case '\r':
        case '\t': line++;
                   break;
        default  : line++;
                   blank = 0;
                   break;
        case 0   : return 0;
        case '\n': path->lines++;
                   path->blanks += blank;
                   blank = 1;
                   line = 0;
        }
    }
    if (line) {
        path->lines++;
        path->blanks += blank;
    }

    plt->unmap(&map);
    path->files = 1;
    return 1;
}

typedef struct {
    Path *totals;
    Mutex lock;
} Totals;

static Bool match(Char16 *a, Char16 *b)
{
    while (*a && *b) {
        if (*a++ != *b++) {
            return 0;
        }
    }
    return *a == *b;
}

static Bool accumulate(Totals *totals, Path *path)
{
    if (!path->files) {
        return 0;
    }

    lock(&totals->lock);
    for (Path *t = totals->totals; t; t = t->next) {
        if (match(path->path, t->path)) {
            t->files++;
            t->lines += path->lines;
            t->blanks += path->blanks;
            unlock(&totals->lock);
            return 0;
        }
    }
    path->next = totals->totals;
    totals->totals = path;
    unlock(&totals->lock);
    return 1;
}

typedef struct {
    Path **slots;
    Path *freelist;
    Totals *totals;
    #if DEBUG
    Size wakes, waits;
    #endif
    unsigned mask;
    unsigned head;
    unsigned tail;
    unsigned completed;
    Mutex slotlock;
    Mutex freelock;
    Bool shutdown;
} WorkQueue;

static WorkQueue *newqueue(Arena *a, int exp, Totals *totals)
{
    WorkQueue *q = NEW(a, WorkQueue);
    Size len = (Size)1 << exp;
    q->mask = len - 1;
    q->slots = ARRAY(a, Path *, len);
    q->totals = totals;

    return q;
}

static Path *newpath(Arena *a, WorkQueue *q)
{
    lock(&q->freelock);
    Path *path = q->freelist;
    if (path) {
        q->freelist = path->next;
        unlock(&q->freelock);
        ZERO(path);
    } else {
        unlock(&q->freelock);
        path = NEW(a, Path);
    }
    return path;
}

static void freepath(WorkQueue *q, Path *path)
{
    lock(&q->freelock);
    path->next = q->freelist;
    q->freelist = path;
    unlock(&q->freelock);
}

static Path *pop(Platform *plt, WorkQueue *q)
{
    for (int tries = 0;; tries++) {
        lock(&q->slotlock);
        unsigned head = q->head;
        if (q->head != q->tail) {
            Path *path = q->slots[q->tail++ & q->mask];
            unlock(&q->slotlock);
            return path;
        }
        unlock(&q->slotlock);

        if (__atomic_load_n(&q->shutdown, __ATOMIC_RELAXED)) {
            return 0;
        }

        if (tries < 1<<8) {
            PAUSE;
        } else {
            #if DEBUG
            __atomic_fetch_add(&q->waits, 1, __ATOMIC_RELAXED);
            #endif
            plt->wait(&q->head, head);
            tries = 0;
        }
    }
}

static Bool push(Platform *plt, WorkQueue *q, Path *path)
{
    lock(&q->slotlock);
    unsigned nexthead = (q->head + 1) & q->mask;
    unsigned masktail = q->tail & q->mask;
    if (nexthead == masktail) {
        unlock(&q->slotlock);
        return 0;  // no room
    }
    Bool wake = q->head == q->tail;
    q->slots[q->head++ & q->mask] = path;
    unlock(&q->slotlock);
    if (wake) {
        #if DEBUG
        __atomic_fetch_add(&q->wakes, 1, __ATOMIC_RELAXED);
        #endif
        plt->wakeall(&q->head);
    }
    return 1;
}

static void complete(Platform *plt, WorkQueue *q)
{
    __atomic_add_fetch(&q->completed, 1, __ATOMIC_SEQ_CST);
    lock(&q->slotlock);
    Bool wake = q->completed == q->head;
    unlock(&q->slotlock);
    if (wake) {
        #if DEBUG
        __atomic_fetch_add(&q->wakes, 1, __ATOMIC_RELAXED);
        #endif
        plt->wake(&q->completed);
    }
}

static void wait(Platform *plt, WorkQueue *q)
{
    // NOTE: q->head is not stored concurrently, so locking is unnecessary
    unsigned target = q->head;

    // If threads cannot wait, request termination.
    __atomic_store_n(&q->shutdown, 1, __ATOMIC_RELAXED);

    // Help finish the queue
    for (;;) {
        Path *path = pop(plt, q);
        if (!path) {
            break;
        }
        tally(plt, path);
        if (!accumulate(q->totals, path)) {
            freepath(q, path);
        }
        complete(plt, q);
    }

    // Wait for completion
    for (;;) {
        unsigned got = __atomic_load_n(&q->completed, __ATOMIC_SEQ_CST);
        if (got == target) {
            return;
        }
        #if DEBUG
        __atomic_fetch_add(&q->waits, 1, __ATOMIC_RELAXED);
        #endif
        plt->wait(&q->completed, got);
    }
}

typedef struct {
    Path *head;
    Path *tail;
} Dirs;

static void append(Dirs *dirs, Path *path)
{
    path->next = 0;
    if (dirs->tail) {
        dirs->tail->next = path;
    } else {
        dirs->head = path;
    }
    dirs->tail = path;
}

static Path *unshift(Dirs *dirs)
{
    Path *path = dirs->head;
    if (dirs->head == dirs->tail) {
        dirs->head = dirs->tail = 0;
    } else {
        dirs->head = dirs->head->next;
    }
    return path;
}

typedef struct {
    Byte *buf;
    Size len;
    Size cap;
    Platform *plt;
    int fd;
    Bool error;
} Out;

static Out *newout(Platform *plt, Arena *a, Size cap, int fd)
{
    Out *out = NEW(a, Out);
    out->cap = cap;
    out->buf = ARRAY(a, Byte, out->cap);
    out->plt = plt;
    out->fd = fd;
    return out;
}

static Out *newstdout(Platform *plt, Arena *a)
{
    return newout(plt, a, 1<<12, 1);
}

static Out *newstderr(Platform *plt, Arena *a)
{
    return newout(plt, a, 1<<7, 2);
}

static Out *newmemout(Arena *a, Byte *buf, Size len)
{
    Out *out = NEW(a, Out);
    out->buf = buf;
    out->cap = len;
    out->fd  = -1;
    return out;
}

static void flush(Out *out)
{
    if (!out->error) {
        if (out->fd == -1) {
            out->error |= 1;
        } else if (out->len) {
            out->error |= !out->plt->write(out->fd, out->buf, out->len);
            out->len = 0;
        }
    }
}

static Size outbytes(Out *out, Byte *b, Size len)
{
    Byte *end = b + len;
    while (!out->error && b<end) {
        int avail = out->cap - out->len;
        Size left = end - b;
        int amount = avail<left ? avail : left;

        for (int i = 0; i < amount; i++) {
            out->buf[out->len+i] = b[i];
        }
        b += amount;
        out->len += amount;

        if (out->len == out->cap) {
            flush(out);
        }
    }
    return len;
}

static Size outbyte(Out *out, Byte b)
{
    outbytes(out, &b, 1);
    return 1;
}

static Size outint64(Out *out, int width, Int64 x)
{
    Byte tmp[32];
    ASSERT(width <= SIZEOF(tmp));
    Byte *end = tmp + SIZEOF(tmp);
    Byte *p = end;
    Int64 t = x>0 ? -x : x;
    do {
        *--p = '0' - t%10;
    } while (t /= 10);
    if (x < 0) {
        *--p = '-';
    }
    while (end-p < width) {
        *--p = ' ';
    }
    outbytes(out, p, end-p);
    return end - p;
}

static Size outwstr(Out *out, Char16 *s)
{
    Size len = 0;
    while (s[len]) {
        Char16 c = s[len++];
        if (c < 0x80) {
            outbyte(out, c);
        } else if (c < 0x800) {
            outbyte(out, 0xc0 | ((c >>  6)       ));
            outbyte(out, 0x80 | ((c >>  0) & 0x3f));
        } else {
            outbyte(out, 0xe0 | ((c >> 12)       ));
            outbyte(out, 0x80 | ((c >>  6) & 0x3f));
            outbyte(out, 0x80 | ((c >>  0) & 0x3f));
        }
    }
    return len;
}

typedef struct {
    Platform *plt;
    Arena *arena;
    Out *stderr;
    Totals *totals;
    WorkQueue *queue;
    Dirs *dirs;
    Size limit;
    Bool heading;
    Bool fastquit;
} Cloc;

static void clocthread(void *context)
{
    Cloc *cloc = context;
    Platform *plt = cloc->plt;
    WorkQueue *q = cloc->queue;
    for (;;) {
        Path *path = pop(plt, q);
        if (!path) {
            // NOTE: Mainly in case RtlWaitOnAddress wasn't available,
            // to avoiding spinning during the final tally and printout.
            // It's not important that the thread actually terminates.
            break;
        }
        tally(plt, path);
        if (!accumulate(q->totals, path)) {
            freepath(q, path);
        }
        complete(plt, q);
    }
}

static Path *fromstr(Arena *a, WorkQueue *q, Char16 *dir, Char16 *name)
{
    int i = 0;
    Path *p = newpath(a, q);
    while (i < SIZEOF(p->path)-2 && *dir) {
        p->path[i++] = *dir++;
    }

    p->path[i++] = '\\';

    while (i<SIZEOF(p->path) && *name) {
        p->path[i++] = *name++;
    }

    if (i == SIZEOF(p->path)) {
        freepath(q, p);
        p = 0;
    }
    return p;
}

static Path *merge(Path *left, Path *right)
{
    if (!left) {
        return right;
    } else if (!right) {
        return left;
    }

    Path *head = 0;
    Path **tail = &head;
    while (left && right) {
        Path *p;
        if (pathcmp(left, right) <= 0) {
            p = left;
            left = left->next;
        } else {
            p = right;
            right = right->next;
        }
        *tail = p;
        tail = &p->next;
    }

    if (left) {
        *tail = left;
    } else if (right) {
        *tail = right;
    } else {
        *tail = 0;
    }
    return head;
}

static Path *sort(Path *list)
{
    Size len = 0;
    Path *right = list;
    Path *prev = list;
    for (Path *p = list; p; p = p->next) {
        if (len++ & 1) {
            prev = right;
            right = right->next;
        }
    }
    if (len <= 1) {
        return list;
    }

    prev->next = 0;
    return merge(sort(list), sort(right));
}

static Path *truncate(Path *list, Size newlen)
{
    Path **tail = &list;
    for (Path *p = list; newlen-- && p; p = p->next) {
        tail = &p->next;
    }
    *tail = 0;
    return list;
}

static int maxlen(Path *list, int max)
{
    for (Path *p = list; p; p = p->next) {
        int len = pathlen(p);
        max = len>max ? len : max;
    }
    return max;
}

static void padcolumn(Out *out, int width)
{
    for (int i = 0; i < width; i++) {
        outbyte(out, ' ');
    }
}

typedef struct {
    Char16 *optarg;
    int optind, optopt, optpos;
} GetOpt;

static int wgetopt(GetOpt *x, int argc, Char16 **argv, char *optstring)
{
    x->optind += !x->optind;
    Char16 *arg = x->optind<argc ? argv[x->optind] : 0;
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

static Bool usage(Out *out)
{
    OUTSTR(out, "usage: cloc [-hq] [-n INT] [DIR]...\n");
    OUTSTR(out, "  -h      print this help message\n");
    OUTSTR(out, "  -n INT  only display the top INT entries\n");
    OUTSTR(out, "  -q      do not print column headings\n");
    flush(out);
    return out->error;
}

static Size parsesize(Char16 *s)
{
    Size len = 0;
    Size size = 0;
    for (; s[len]; len++) {
        Char16 v = s[len] - '0';
        if (v > 9) {
            return -1;
        }
        if (size > (Size_MAX - v)/10) {
            // NOTE: Saturate to Size_MAX, but continue validating.
            size = Size_MAX;
        } else {
            size = size*10 + v;
        }
    }
    return len ? size : -1;
}

static void *clocinit(Platform *plt, int argc, Char16 **argv)
{
    Arena *a = placearena(plt->heap, plt->heapsize);
    Out *stderr = newstderr(plt, a);  // pre-allocate in case of OOM
    if (SAVEPOINT(a)) {
        OUTSTR(stderr, "cloc: out of memory\n");
        flush(stderr);
        return 0;
    }

    GetOpt *wgo = NEW(a, GetOpt);
    Cloc *cloc = NEW(a, Cloc);
    cloc->plt = plt;
    cloc->arena = a;
    cloc->stderr = stderr;
    cloc->totals = NEW(a, Totals);
    cloc->queue = newqueue(a, 14, cloc->totals);
    cloc->dirs = NEW(a, Dirs);
    cloc->limit = -1;
    cloc->heading = 1;
    cloc->fastquit = 0;

    for (int option; (option = wgetopt(wgo, argc, argv, "hn:q")) != -1;) {
        switch (option) {
        case 'h':
            cloc->fastquit = 1;
            return usage(newstdout(plt, a)) ? 0 : cloc;
        case 'n':
            cloc->limit = parsesize(wgo->optarg);
            if (cloc->limit < 0) {
                OUTSTR(stderr, "cloc: invalid -n: \"");
                outwstr(stderr, wgo->optarg);
                OUTSTR(stderr, "\"\n");
                flush(stderr);
                return 0;
            }
            break;
        case 'q':
            cloc->heading = 0;
            break;
        default:
            usage(stderr);
            return 0;
        }
    }

    if (wgo->optind == argc) {
        append(cloc->dirs, fromstr(a, cloc->queue, L".", L""));
    } else {
        for (int i = wgo->optind; i < argc; i++) {
            append(cloc->dirs, fromstr(a, cloc->queue, argv[i], L""));
        }
    }

    return cloc;
}

static int clocmain(void *context)
{
    Cloc *cloc = context;
    Platform *plt = cloc->plt;
    Arena *a = cloc->arena;
    if (SAVEPOINT(a)) {
        OUTSTR(cloc->stderr, "cloc: out of memory\n");
        flush(cloc->stderr);
        return 0;
    }

    Dirs *dirs = cloc->dirs;
    WorkQueue *queue = cloc->queue;
    Totals *totals = cloc->totals;

    for (;;) {
        Path *dir = unshift(dirs);
        if (!dir) {
            break;
        }

        PlatformDir handle;
        if (!plt->diropen(&handle, dir->path)) {
            freepath(queue, dir);
            continue;
        }

        while (plt->dirnext(&handle)) {
            if (handle.name[0] == '.') {
                continue;
            } else if (handle.dir) {
                Path *nextdir = fromstr(a, queue, dir->path, handle.name);
                if (!nextdir) continue;
                append(dirs, nextdir);
            } else {
                Path *path = fromstr(a, queue, dir->path, handle.name);
                if (!path) continue;
                if (!push(plt, queue, path)) {
                    tally(plt, path);
                    if (!accumulate(totals, path)) {
                        freepath(queue, path);
                    }
                }
            }
        }
        freepath(queue, dir);
    }
    wait(plt, queue);

    totals->totals = sort(totals->totals);
    if (cloc->limit >= 0) {
        totals->totals = truncate(totals->totals, cloc->limit);
    }

    #if DEBUG
    // NOTE: Final stats help with tuning the queue size. Larger queues
    // means less wait/wake but more memory use. The goal is to make the
    // queue just large enough that wait/wake is very low, but no larger
    // since that quickly ramps up memory use (more live Path objects).
    Byte msg[128];
    ZERO(&msg);
    Out *dbg = newmemout(a, msg, SIZEOF(msg)-1);
    outint64(dbg, 0, a->off >> 10);
    OUTSTR(dbg, "KiB, ");
    outint64(dbg, 0, queue->waits);
    OUTSTR(dbg, " waits, ");
    outint64(dbg, 0, queue->wakes);
    OUTSTR(dbg, " wakes\n");
    plt->debug(msg);
    #endif

    Out *stdout = newstdout(plt, a);

    int extwidth = 1;
    if (cloc->heading) {
        int heading = OUTSTR(stdout, "extension");
        extwidth += maxlen(totals->totals, heading);
        padcolumn(stdout, extwidth-heading);
        OUTSTR(stdout, "   files    blanks     lines\n");
    } else {
        extwidth += maxlen(totals->totals, 6);
    }

    for (Path *t = totals->totals; t; t = t->next) {
        Size width = extwidth;
        if (t->path[0]) {
            width -= outbyte(stdout, '.');
            width -= outwstr(stdout, t->path);
        } else {
            width -= OUTSTR(stdout, "(none)");
        }
        padcolumn(stdout, width);

        outint64(stdout, 8, t->files);
        outint64(stdout, 10, t->blanks);
        outint64(stdout, 10, t->lines);
        outbyte(stdout, '\n');
    }
    flush(stdout);
    return stdout->error;
}


// Win32 Platform

typedef Usize Handle;

typedef struct {
    Uint32 attr;
    Uint32 create[2], access[2], write[2];
    Uint32 size[2];
    Uint32 reserved1[2];
    Char16 name[Path_MAX];
    Char16 altname[14];
    Uint32 reserved2[2];
} FindData;  // a.k.a. WIN32_FIND_DATAW

Handle FindFirstFileW(Char16 *, FindData *)
    __attribute__((dllimport,stdcall));
char FindNextFileW(Handle, FindData *)
    __attribute__((dllimport,stdcall));
char FindClose(Handle)
    __attribute__((dllimport,stdcall));

Char16 **CommandLineToArgvW(Char16 *, int *)
    __attribute__((stdcall,dllimport,malloc));
Char16 *GetCommandLineW(void)
    __attribute__((stdcall,dllimport,malloc));

void ExitProcess(int)
    __attribute__((dllimport,stdcall,noreturn));

Uint32 GetFileSize(Handle, Uint32 *)
    __attribute__((dllimport,stdcall));

void *GetProcAddress(Handle, void *)
    __attribute__((stdcall,dllimport));
Handle LoadLibraryA(void *)
    __attribute__((stdcall,dllimport));

Handle GetStdHandle(int)
    __attribute__((dllimport,stdcall));
char WriteFile(Handle, void *, int, int *, void *)
    __attribute__((dllimport,stdcall));

char CloseHandle(Handle)
    __attribute__((stdcall,dllimport));
Handle CreateFileMappingA(Handle, void *, int, Uint32, Uint32, void *)
    __attribute__((stdcall,dllimport));
Handle CreateFileW(Char16 *, int, int, void *, int, int, void *)
    __attribute__((dllimport,stdcall));
void *MapViewOfFile(Handle, int, Uint32, Uint32, Size)
    __attribute__((stdcall,dllimport,malloc));
char UnmapViewOfFile(void *)
    __attribute__((stdcall,dllimport));

Handle CreateThread(void *, Size, int (__stdcall*)(void *), void *, int, int *)
    __attribute__((dllimport,stdcall));
void GetSystemInfo(void *)
    __attribute__((dllimport,stdcall));
void OutputDebugStringA(void *)
    __attribute__((stdcall,dllimport));
void *VirtualAlloc(void *, Size, int, int)
    __attribute__((dllimport,stdcall,malloc));

static Bool win32_write(int fd, void *buf, Size len)
{
    // TODO: GetConsoleMode + WriteConsole
    // On the other hand, the only unicode text in the output is the
    // file extension listings. How often are these non-ASCII?
    ASSERT(len < (Size)(-1u>>1));
    int dummy;
    Handle h = GetStdHandle(-10 - fd);
    return WriteFile(h, buf, len, &dummy, 0);
}

static Bool win32_map(PlatformMap *map, Char16 *path)
{
    map->buf = 0;
    map->len = 0;

    Handle file = CreateFileW(path, 0x80000000u, 7, 0, 3, 128, 0);
    if (file == (Handle)-1) {
        return 0;
    }

    Uint32 hi, lo;
    lo = GetFileSize(file, &hi);
    Uint64 size = (Uint64)hi<<32 | lo;
    if (size > Size_MAX) {
        CloseHandle(file);
        return 0;
    } else if (!lo) {
        CloseHandle(file);
        return 1;
    }
    Size len = size;

    Handle m = CreateFileMappingA(file, 0, 2, hi, lo, 0);
    CloseHandle(file);
    if (!m) {
        return 0;
    }

    Byte *buf = MapViewOfFile(m, 4, 0, 0, lo);
    CloseHandle(m);
    if (!buf) {
        return 0;
    }

    map->buf = buf;
    map->len = len;
    return 1;
}

static void win32_unmap(PlatformMap *m)
{
    // NOTE: The map limit on x64 is practically unlimited, even on the
    // largest source code directories, so don't waste time unmapping
    // individual files. Since these are backed by real files, not the
    // page file, leaving these mappings alive is cheap.
    #ifndef _WIN64
    UnmapViewOfFile(m->buf);
    #endif
}

static Bool win32_diropen(PlatformDir *dir, Char16 *path)
{
    ASSERT(path[0]);

    int len = 0;
    Char16 glob[Path_MAX+2];
    for (len = 0; path[len]; len++) {
        ASSERT(len < Path_MAX-1);
        glob[len] = path[len];
    }
    if (glob[len-1]!='/' && glob[len-1]!='\\') {
        glob[len++] = '\\';
    }
    glob[len++] = '*';
    glob[len] = 0;

    FindData fd;
    Handle h = FindFirstFileW(glob, &fd);
    if (h == (Handle)-1) {
        return 0;
    }
    Bool hidden = !!(fd.attr&0x02);

    dir->handle = (void *)h;
    for (int i = 0; i < Path_MAX; i++) {
        dir->name[i] = fd.name[i];
    }
    dir->dir = !!(fd.attr&0x10);
    dir->first = !hidden;
    return 1;
}

static Bool win32_dirnext(PlatformDir *dir)
{
    if (dir->first) {
        dir->first = 0;
        return 1;
    }

    FindData fd;
    while (FindNextFileW((Handle)dir->handle, &fd)) {
        Bool hidden = !!(fd.attr&0x02);
        if (!hidden) {
            dir->dir = !!(fd.attr&0x10);
            for (int i = 0; i < Path_MAX; i++) {
                dir->name[i] = fd.name[i];
            }
            return 1;
        }
    }

    FindClose((Handle)dir->handle);
    return 0;
}

static Int32 (*win32_RtlWaitOnAddress)(void *, void *, Size, void *)
    __attribute__((stdcall));
static Int32 (*win32_RtlWakeAddressSingle)(void *)
    __attribute__((stdcall));
static Int32 (*win32_RtlWakeAddressAll)(void *)
    __attribute__((stdcall));

static void win32_wait(unsigned *addr, unsigned current)
{
    if (win32_RtlWaitOnAddress) {
        win32_RtlWaitOnAddress(addr, &current, sizeof(*addr), 0);
    } else {
        PAUSE;
    }
}

static void win32_wake(unsigned *addr)
{
    if (win32_RtlWakeAddressSingle) {
        win32_RtlWakeAddressSingle(addr);
    }
}

static void win32_wakeall(unsigned *addr)
{
    if (win32_RtlWakeAddressAll) {
        win32_RtlWakeAddressAll(addr);
    }
}

static void win32_debug(Byte *msg)
{
    OutputDebugStringA(msg);
}

static int numcores(void)
{
    struct {
        int a, b;
        void *c, *d, *e;
        int f, g, h, i;
    } tmp;
    GetSystemInfo(&tmp);
    ASSERT(tmp.f > 0);
    return tmp.f;
}

__attribute__((stdcall))
static int win32_thread(void *context)
{
    clocthread(context);
    return 0;
}

__attribute__((externally_visible))
void mainCRTStartup(void)
{
    // NOTE: Manually load the futex API. It's only available in more
    // recent Windows releases, plus it's nicer not directly link with
    // ntdll.dll. Everything still works correctly with the "fake" no-op
    // implementations, just a bit less efficiently.
    Handle ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll) {
        win32_RtlWaitOnAddress =
            GetProcAddress(ntdll, "RtlWaitOnAddress");
        win32_RtlWakeAddressSingle =
            GetProcAddress(ntdll, "RtlWakeAddressSingle");
        win32_RtlWakeAddressAll =
            GetProcAddress(ntdll, "RtlWakeAddressAll");
    }

    Platform plt = {0};
    plt.heapsize = (Size)1 << 28;
    plt.heap = VirtualAlloc(0, plt.heapsize, 0x3000, 4);
    plt.write = win32_write;
    plt.map = win32_map;
    plt.unmap = win32_unmap;
    plt.diropen = win32_diropen;
    plt.dirnext = win32_dirnext;
    plt.wait = win32_wait;
    plt.wake = win32_wake;
    plt.wakeall = win32_wakeall;
    plt.debug = win32_debug;

    int argc;
    Char16 **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    void *context = clocinit(&plt, argc, argv);
    if (!context) {
        ExitProcess(2);
    }

    int numproc = (numcores() + 1) / 2;
    for (int i = 0; i < numproc; i++) {
        CloseHandle(CreateThread(0, 0, win32_thread, context, 0, 0));
    }
    ExitProcess(clocmain(context));
}