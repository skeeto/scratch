// where's all the code? (non-interactive version)
// Counts lines in a source tree and prints the biggest portion of the tree.
//
// Build (GCC):
//   gcc -municode -O3 -o watc.exe watc.c
// Build (MSVC):
//   cl /O2 watc.c
//
// Inspired by Ted Unangst's original, interactive watc:
//   https://humungus.tedunangst.com/r/watc
//   https://flak.tedunangst.com/post/watc
//
// This is free and unencumbered software released into the public domain.
#define WIN32_LEAN_AND_MEAN
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <windows.h>

// The purpose of multi-threading isn't parallelism but concurrency. This
// program hardly does any work itself, and it has much better performance
// when the slow I/O calls (open, read, close) are overlapped. It's not
// important that the number of threads matches CPU cores, but just that it
// has enough I/O overlap.
#ifndef NTHREADS
#  define NTHREADS 4
#endif

// Atomics
#if __GNUC__
#  define ATOMIC_LOAD(a)       __atomic_load_n(a, __ATOMIC_ACQUIRE)
#  define ATOMIC_RLOAD(a)      __atomic_load_n(a, __ATOMIC_RELAXED)
#  define ATOMIC_RSTORE(a, v)  __atomic_store_n(a, v, __ATOMIC_RELAXED)
#  define ATOMIC_ADD(a, c)     __atomic_add_fetch(a, c, __ATOMIC_RELEASE)
#  define ATOMIC_RADD(a, c)    __atomic_add_fetch(a, c, __ATOMIC_RELAXED)
#  define ATOMIC_AND(a, m)     __atomic_and_fetch(a, m, __ATOMIC_RELEASE)
#  define ATOMIC_CAS(a, e, d)  __atomic_compare_exchange_n( \
       a, e, d, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED)
#elif _MSC_VER
#  include <winnt.h>
#  define ATOMIC_LOAD(a)       InterlockedOr((long *)a, 0)
#  define ATOMIC_RLOAD(a)      *(a)
#  define ATOMIC_RSTORE(a, v)  *(a) = v
#  define ATOMIC_ADD(a, c)     InterlockedAdd((long *)a, c)
#  define ATOMIC_RADD(a, c)    InterlockedAdd((long *)a, c)
#  define ATOMIC_AND(a, m)     InterlockedAnd((long *)a, m)
#  define ATOMIC_CAS(a, e, d)  \
       (InterlockedCompareExchange((long *)a, d, *e) == (long)*e)
#endif

static const wchar_t charset_fancy[] = {0x2502, 0x2514, 0x251c, 0x2500};
static const wchar_t charset_ascii[] = {   '|',    '`',    '|',    '-'};

// Large source trees have on the order of 1,000 directories. The very
// largest are on the order of 10,000 directories.
#define DIRS_MAX  (1<<17)

struct dir {
    uint64_t nbytes;
    uint32_t nlines;
    int32_t  name;      // off/len into a struct buf
    int32_t  link;      // index of parent / first child
    int32_t  nsubdirs;
};

// Large source trees have on the order of cumulatively 10,000 runes of
// directory names. The very largest have on the order of 100,000 runes.
#define BUF_MAX (INT32_C(1)<<22)
struct buf {
    int32_t len;
    wchar_t buf[BUF_MAX];
};

// Append the null-terminated string to the buffer, returning its encoded
// off/len value for later retrieval.
static int32_t
buf_push(struct buf *b, wchar_t *s)
{
    int32_t off = b->len;
    int32_t len = (int)wcslen(s);
    if (b->len+len > BUF_MAX) {
        return -1;
    }
    memcpy(b->buf+off, s, len*sizeof(*s));
    b->len += len;
    return len<<22 | off;
}

// Decode a buffer string length from an encoded off/len.
static int
str_len(int32_t s)
{
    return s >> 22;
}

// Decode a buffer string offset from an encoded off/len.
static int32_t
str_off(int32_t s)
{
    return s & 0x3fffff;
}

// Return 1 if the null-terminated string has a source file extension.
static int
issource(wchar_t *w)
{
    // a perfect hash for C, C++, asm, Go, and Rust source file extensions
    #define HASHM 0x20026eba
    static const uint64_t t[16] = {
        0xffffe0068e0d5590, 0xffffe0052e196bf1, 0xe0063200998a4042,
        0xffffe0072df29793, 0xe00a3256b1621294, 0xe007921dfba97d35,
        0xe005b1f45e783756, 0x9255e8d39e48ad27, 0xe009b24a76508768,
        0x91fc109d148fd0a9, 0xe00b927213810fda, 0x3263528dcd0e3d1b,
        0xffffe00a8dbf6cdc, 0xffffe0092dcb833d, 0x32097a584aca938e,
        0xffffe00b2da4aedf,
    };
    uint64_t h = 0;
    for (wchar_t *c = w; *c; c++) {
        if (*c == '.') {
            h = (uint64_t)-1;
        } else {
            h = h*65537 + *c;
        }
    }
    h *= HASHM;
    h ^= h >> 32;
    return t[h&15] == h;
}

// Construct a path to a given file.
static void
buildpath(wchar_t *w, wchar_t *buf, struct dir *dirs, int32_t d, int32_t f)
{
    int n = 0;
    int32_t chain[MAX_PATH/2];
    for (int32_t j = d; j > 0; j = dirs[j].link) {
        chain[n++] = j;
    }

    for (n--; n >= 0; n--) {
        int32_t name = dirs[chain[n]].name;
        int len = str_len(name);
        int32_t off = str_off(name);
        memcpy(w, buf+off, len*sizeof(*w));
        w += len;
        *w++ = '\\';
    }

    int len = str_len(f);
    int32_t off = str_off(f);
    memcpy(w, buf+off, len*(sizeof(*w)));
    w += len;

    *w = 0;
}

// Count the lines in a file, returning -1 on error.
static long
countlines(wchar_t *filename)
{
    HANDLE h = CreateFileW(
        filename,
        GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_DELETE,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0
    );
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    DWORD n;
    char buf[1<<12];
    long c = 0;
    int last = '\n';
    while (ReadFile(h, buf, sizeof(buf), &n, 0) && n) {
        if (n < sizeof(buf)) {
            memset(buf+n, 0, sizeof(buf)-n);
        }
        for (int i = 0; i < (int)sizeof(buf); i++) {
            c += buf[i] == '\n';
        }
        last = buf[n-1];
    }
    c += last != '\n';
    if (GetLastError() != ERROR_SUCCESS) {
        c = -1;
    }

    CloseHandle(h);
    return c;
}

static void
processfile(wchar_t *path, struct dir *dirs, int32_t i)
{
    int32_t c = countlines(path);
    if (c < 0) {
        fwprintf(stderr, L"watc: warning: count failed: %ls\n", path);
    } else {
        uint32_t u = c;
        uint32_t nlines = ATOMIC_RADD(&dirs[i].nlines, u);
        if (nlines < u) {
            fwprintf(stderr, L"watc: line count overflow: %ls\n", path);
            exit(1);
        }
    }
}

// Propagate a directory's counts to its ancestors, stopping at the root.
static void
propagate(struct dir *dirs, int32_t i)
{
    for (int32_t j = dirs[i].link; j >= 0; j = dirs[j].link) {
        dirs[j].nbytes += dirs[i].nbytes;
        dirs[j].nlines += dirs[i].nlines;
    }
}

// A lock-free, concurrent work queue
// Ref: https://nullprogram.com/blog/2022/05/14/
#define QUEUE_LEN (1<<15)
struct queue {
    wchar_t *buf;
    struct dir *dirs;
    uint32_t q;
    wchar_t p[QUEUE_LEN][MAX_PATH];
    int32_t d[QUEUE_LEN];
};

// Insert a path and directory index into the front of the queue. Returns 0
// if the queue is full.
static int
queue_send(struct queue *q, int32_t idx, int32_t name)
{
    uint32_t r = ATOMIC_LOAD(&q->q);
    int mask = QUEUE_LEN - 1;
    int head = (r >>  0) & mask;
    int tail = (r >> 16) & mask;
    int next = (head+1u) & mask;
    if (next == tail) {
        return 0;
    }

    ATOMIC_RSTORE((volatile int32_t *)q->p+head, name);
    ATOMIC_RSTORE((volatile int32_t *)q->d+head, idx);

    if (r & 0x8000) {  // avoid overflow on commit
        ATOMIC_AND(&q->q, ~0x8000);
    }
    ATOMIC_ADD(&q->q, 1);
    return 1;
}

// Pop a path and directory index from the back of the queue. Returns 0 if
// the queue is empty.
static int
queue_recv(struct queue *q, int32_t *idx, int32_t *name)
{
    uint32_t r;
    do {
        r = ATOMIC_LOAD(&q->q);
        int mask = QUEUE_LEN - 1;
        int head = (r >>  0) & mask;
        int tail = (r >> 16) & mask;
        if (head == tail) {
            return 0;
        }

        // Individual, relaxed loads will be unlocked and unfenced
        *name = ATOMIC_RLOAD((volatile int32_t *)q->p+tail);
        *idx = ATOMIC_RLOAD((volatile int32_t *)q->d+tail);

    } while (!ATOMIC_CAS(&q->q, &r, r+0x10000));
    return 1;
}

// Worker thread that continuously completes jobs from the queue. Exits when
// it sees a directory index of -1.
static unsigned __stdcall
worker(void *arg)
{
    struct queue *q = arg;
    wchar_t *buf = q->buf;
    struct dir *dirs = q->dirs;
    for (;;) {
        int32_t d;
        int32_t name;
        while (!queue_recv(q, &d, &name));
        if (d == -1) {
            return 0;
        }
        wchar_t path[MAX_PATH];
        buildpath(path, buf, dirs, d, name);
        processfile(path, dirs, d);
    }
}

// Context for dircmp()
static wchar_t *dircmp_buf;

// Compare struct dir by lines (dsc), then name (asc).
static int
dircmp(const void *p0, const void *p1)
{
    const struct dir *a = p0;
    const struct dir *b = p1;
    if (a->nlines == b->nlines) {
        int an = str_len(a->name);
        int bn = str_len(b->name);
        wchar_t *as = dircmp_buf+str_off(a->name);
        wchar_t *bs = dircmp_buf+str_off(b->name);
        int r = wcsncmp(as, bs, an<bn ? an : bn);
        switch (r) {
        case  0: return an > bn ? +1 : -1;
        default: return r;
        }
    } else {
        return a->nlines > b->nlines ? -1 : +1;
    }
}

// Sort each subdirectory listing by nlines/name.
static void
sort(struct dir *dirs, int32_t len, wchar_t *buf)
{
    dircmp_buf = buf;
    for (int32_t i = 0; i < len; i++) {
        struct dir *beg = dirs + dirs[i].link;
        qsort(beg, dirs[i].nsubdirs, sizeof(*dirs), dircmp);
    }
}

static int
human(wchar_t *s, size_t n, double z, double f)
{
    int i = 0;
    for (; z >= f; z /= f) {
        i++;
    }
    switch (i) {
    case  0: swprintf(s, n, L"%d", (int)z); break;
    default: swprintf(s, n, L"%.2f%c", z, "kMGTPE"[i-1]);
    }
    return i;
}

static void
printstat(struct dir *d, wchar_t *buf)
{
    wchar_t h[2][32];
             human(h[0], 32, (double)d->nlines, 1000);
    int bi = human(h[1], 32, (double)d->nbytes, 1024);
    wprintf(L"%.*ls %lsLOC %ls%ls\n",
            str_len(d->name), buf+str_off(d->name),
            h[0], h[1], bi ? L"iB" : L"B");
}

struct config {
    long vlim, dlim;
    wchar_t charset[4];
};

// Print a portion of a line-counted source tree.
static void
print(struct dir *dirs, wchar_t *buf, int32_t other, struct config cfg)
{
    int n = 0;
    struct {
        int32_t d;
        int32_t i;
    } stack[MAX_PATH/2];

    stack[n].d = 0;
    stack[n].i = 0;
    printstat(dirs+0, buf);
    cfg.vlim--;
    cfg.dlim--;

    while (n >= 0) {
        int32_t d = stack[n].d;
        int32_t i = stack[n].i;
        if (i >= dirs[d].nsubdirs) {
            n--;
            continue;
        }
        int32_t c = dirs[d].link + i;

        for (int t = 0; t < n; t++) {
            int32_t td = stack[t].d;
            int32_t ti = stack[t].i;
            wchar_t tc = ti<dirs[td].nsubdirs ? cfg.charset[0] : ' ';
            wprintf(L"%lc", tc);
            wprintf(L"%lc", L' ');
        }

        int last;
        if (cfg.vlim == 0 || n > cfg.dlim) {
            dirs[c].name = other;
            for (int32_t j = i+1; j < dirs[d].nsubdirs; j++) {
                dirs[c].nbytes += dirs[dirs[d].link+j].nbytes;
                dirs[c].nlines += dirs[dirs[d].link+j].nlines;
            }
            n--;
            last = 1;
        } else {
            cfg.vlim--;
            stack[n].i++;
            if (dirs[c].nsubdirs) {
                n++;
                stack[n].d = c;
                stack[n].i = 0;
            }
            last = i == dirs[d].nsubdirs-1;
        }
        wprintf(L"%lc", last ? cfg.charset[1] : cfg.charset[2]);
        wprintf(L"%lc", cfg.charset[3]);
        printstat(dirs+c, buf);
    }
}

#define WGETOPT_INIT {0, 0, 0, 0}
struct wgetopt {
    wchar_t *optarg;
    int optind, optopt, optpos;
};

static int
wgetopt(struct wgetopt *x, int argc, wchar_t **argv, char *optstring)
{
    wchar_t *arg = argv[!x->optind ? (x->optind += !!argc) : x->optind];
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
            } else if (argv[x->optind+1]) {
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

static int
cpu_count(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
}

static void
usage(FILE *f)
{
    static const wchar_t usage[] =
    L"usage: watc [-Ah] [-n LIMIT] [-d LIMIT] [DIR]\n"
    L"  -A         draw using ASCII characters\n"
    L"  -d LIMIT   max depth to print\n"
    L"  -h         print this help message\n"
    L"  -n LIMIT   max individuals to print\n";
    fwprintf(f, usage);
}

int
wmain(int argc, wchar_t **argv)
{
    _setmode(1, _O_U8TEXT);
    _setmode(2, _O_U8TEXT);

    struct config cfg = {
        16, MAX_PATH/2,
        {charset_fancy[0], charset_fancy[1],
         charset_fancy[2], charset_fancy[3]}
    };

    struct wgetopt wgo = WGETOPT_INIT;
    int option;
    while ((option = wgetopt(&wgo, argc, argv, "Ad:hn:")) != -1) {
        switch (option) {
        case 'A': cfg.charset[0] = charset_ascii[0];
                  cfg.charset[1] = charset_ascii[1];
                  cfg.charset[2] = charset_ascii[2];
                  cfg.charset[3] = charset_ascii[3];
                  break;
        case 'd': cfg.dlim = wcstol(wgo.optarg, 0, 10);
                  if (cfg.dlim <= 0) {
                      fwprintf(stderr, L"watc: -d: invalid limit\n");
                      return 1;
                  }
                  break;
        case 'h': usage(stdout);
                  fflush(stdout);
                  return ferror(stdout);
        case 'n': cfg.vlim = wcstol(wgo.optarg, 0, 10);
                  if (cfg.vlim <= 0) {
                      fwprintf(stderr, L"watc: -n: invalid limit\n");
                      return 1;
                  }
                  break;
        case ':': fwprintf(stderr, L"watc: missing argument: -%c\n",
                           wgo.optopt);
                  usage(stderr);
                  return 1;
        default : fwprintf(stderr, L"watc: unknown option: -%c\n",
                           wgo.optopt);
                  usage(stderr);
                  return 1;
        }
    }

    wchar_t *dir = argv[wgo.optind];
    switch (argc - wgo.optind) {
    default: fwprintf(stderr, L"watc: too many positional arguments\n");
             usage(stderr);
             return 1;
    case  0: break;
    case  1: if (!SetCurrentDirectoryW(dir)) {
                fwprintf(stderr, L"watc: change directory failed: %ls\n", dir);
                return 1;
             }
    }

    // All substantial allocations
    static struct buf buf;
    static struct dir dirs[DIRS_MAX];
    static struct queue queue;

    // Allocate special strings
    int32_t other = buf_push(&buf, L"(other)");
    int32_t glob = buf_push(&buf, L"*");

    // Initialize queue with root directory
    int32_t ndirs = 1;
    dirs[0].name = buf_push(&buf, L".");
    dirs[0].link = -1;

    // Don't start more threads than CPUs
    int nthreads = NTHREADS;
    int ncpu = cpu_count();
    nthreads = ncpu < nthreads ? ncpu : nthreads;

    // Spin up N-1 worker threads. The current thread will also participate
    // in the work queue as a consumer.
    HANDLE thr[NTHREADS-1];
    queue.buf = buf.buf;
    queue.dirs = dirs;
    for (int i = 0; i < nthreads-1; i++) {
        thr[i] = (HANDLE)_beginthreadex(0, 0, worker, &queue, 0, 0);
    }

    for (int32_t i = 0; i < ndirs; i++) {
        wchar_t path[MAX_PATH];
        buildpath(path, buf.buf, dirs, i, glob);

        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(path, &fd);
        if (h == INVALID_HANDLE_VALUE) {
            fwprintf(stderr, L"watc: traversal failure: %ls\n", path);
            continue;
        }

        do {
            DWORD a = fd.dwFileAttributes;

            if (fd.cFileName[0] == '.' || (a & FILE_ATTRIBUTE_HIDDEN)) {
                continue;
            }

            if (a & FILE_ATTRIBUTE_DIRECTORY) {
                dirs[i].nsubdirs++;
                int32_t c = ndirs++;
                if (c >= DIRS_MAX) {
                    fwprintf(stderr, L"watc: out of memory\n");
                    return 1;
                }
                dirs[c].link = i;

                int32_t name = buf_push(&buf, fd.cFileName);
                if (name < 0) {
                    fwprintf(stderr, L"watc: out of memory\n");
                    return 1;
                }
                dirs[c].name = name;

            } else if (issource(fd.cFileName)) {
                int32_t name = buf_push(&buf, fd.cFileName);
                if (name < 0) {
                    fwprintf(stderr, L"watc: out of memory\n");
                    return 1;
                }

                dirs[i].nbytes += fd.nFileSizeLow;
                dirs[i].nbytes += (uint64_t)fd.nFileSizeHigh << 32;

                if (!queue_send(&queue, i, name)) {
                    wchar_t tmp[MAX_PATH];
                    buildpath(tmp, buf.buf, dirs, i, name);
                    processfile(tmp, dirs, i);
                }
            }
        } while (FindNextFileW(h, &fd));

        if (GetLastError() != ERROR_NO_MORE_FILES) {
            fwprintf(stderr, L"watc: traversal failure: %ls\n", path);
            return 1;
        }
        FindClose(h);
    }

    // Turn into a consumer until the queue empties
    for (;;) {
        int32_t i;
        int32_t name;
        if (!queue_recv(&queue, &i, &name)) {
            break;
        }
        wchar_t path[MAX_PATH];
        buildpath(path, buf.buf, dirs, i, name);
        processfile(path, dirs, i);
    }

    // Wait for worker threads to complete
    for (int i = 0; i < nthreads-1; i++) {
        queue_send(&queue, -1, 0);
    }
    for (int i = 0; i < nthreads-1; i++) {
        WaitForSingleObject(thr[i], INFINITE);
        CloseHandle(thr[i]);
    }

    // Propagate results up the tree
    for (int32_t i = 1; i < ndirs; i++) {
        propagate(dirs, i);
    }

    // Reverse link directions. Previous link points to the parent, now it
    // points to the first child, and due to breadth-first traversal all
    // children are adjacent.
    dirs[0].link = 1;
    for (int32_t i = 1; i < ndirs; i++) {
        dirs[i].link = dirs[i-1].link + dirs[i-1].nsubdirs;
    }

    sort(dirs, ndirs, buf.buf);
    print(dirs, buf.buf, other, cfg);

    fflush(stdout);
    return ferror(stdout);
}
