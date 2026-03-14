#include "culprit.c"

// Virtual filesystem for testing

typedef struct {
    c16 *path;
    c16 *entries;   // null-separated names, double-null terminated
                    // trailing '\\' on a name means it is a directory
    i32 *pids;
    i32  npids;
} VDir;

typedef struct {
    c16 *path;
    i32 *pids;
    i32  npids;
} VFile;

typedef struct {
    c16 *name;
    i32  pid;
} VProc;

struct Plt {
    VDir  *dirs;
    i32    ndirs;
    VFile *files;
    i32    nfiles;
    VProc *procs;
    i32    nprocs;
    c16   *outbuf;
    iz     outlen;
    iz     outcap;
};

static i32 c16cmp(c16 *a, c16 *b)
{
    for (; *a && *a == *b; a++, b++) {}
    return *a - *b;
}

static DirList listdir(Plt *plt, Arena *a, c16 *path)
{
    DirList r = {0, -1};

    // Find directory in virtual filesystem
    VDir *vd = 0;
    for (i32 i = 0; i < plt->ndirs; i++) {
        if (!c16cmp(plt->dirs[i].path, path)) {
            vd = plt->dirs + i;
            break;
        }
    }
    if (!vd) return r;

    // Count entries
    iz count = 0;
    for (c16 *p = vd->entries; *p; ) {
        count++;
        while (*p) p++;
        p++;
    }

    r.data = new(a, count, DirEntry);
    r.len  = 0;

    for (c16 *p = vd->entries; *p; ) {
        c16 *start = p;
        while (*p) p++;
        iz len = p - start;
        p++;  // skip null separator

        // Check for trailing backslash (directory marker)
        i32 isdir = 0;
        if (len > 0 && start[len - 1] == '\\') {
            isdir = 1;
            len--;  // strip the backslash from the name
        }

        c16 *ncopy = new(a, len + 1, c16);
        __builtin_memcpy(ncopy, start, touz(len * (iz)sizeof(c16)));

        r.data[r.len].name  = ncopy;
        r.data[r.len].isdir = isdir;
        r.len++;
    }

    return r;
}

static Pids dirpids(Plt *plt, Arena *a, c16 *path)
{
    Pids r = {0};
    for (i32 i = 0; i < plt->ndirs; i++) {
        if (!c16cmp(plt->dirs[i].path, path)) {
            if (plt->dirs[i].npids > 0) {
                r.len  = plt->dirs[i].npids;
                r.pids = new(a, r.len, i32);
                __builtin_memcpy(r.pids, plt->dirs[i].pids,
                                 touz(r.len * (iz)sizeof(i32)));
            }
            return r;
        }
    }
    return r;
}

static Pids filepids(Plt *plt, Arena *a, c16 **paths, i32 npaths)
{
    Pids r = {0};

    // Collect unique pids across all matching files
    i32 buf[64];
    i32 n = 0;

    for (i32 pi = 0; pi < npaths; pi++) {
        for (i32 fi = 0; fi < plt->nfiles; fi++) {
            if (c16cmp(paths[pi], plt->files[fi].path)) continue;
            for (i32 k = 0; k < plt->files[fi].npids; k++) {
                i32 pid = plt->files[fi].pids[k];
                // Deduplicate
                i32 dup = 0;
                for (i32 d = 0; d < n; d++) {
                    if (buf[d] == pid) { dup = 1; break; }
                }
                if (!dup && n < (i32)(sizeof(buf)/sizeof(*buf))) {
                    buf[n++] = pid;
                }
            }
        }
    }

    if (n > 0) {
        r.len  = n;
        r.pids = new(a, n, i32);
        __builtin_memcpy(r.pids, buf, touz(n * (iz)sizeof(i32)));
    }
    return r;
}

static Str16 pidname(Plt *plt, Arena *a, i32 pid)
{
    Str16 r = {0};
    for (i32 i = 0; i < plt->nprocs; i++) {
        if (plt->procs[i].pid == pid) {
            Str16 name = fromcstr16(plt->procs[i].name);
            r.data = new(a, name.len, c16);
            r.len  = name.len;
            __builtin_memcpy(r.data, name.data,
                             touz(name.len * (iz)sizeof(c16)));
            return r;
        }
    }
    return r;
}

static i32 write16(Plt *plt, i32 fd, Str16 s)
{
    (void)fd;
    iz need = plt->outlen + s.len;
    if (need > plt->outcap) return 0;
    __builtin_memcpy(plt->outbuf + plt->outlen, s.data,
                     touz(s.len * (iz)sizeof(c16)));
    plt->outlen += s.len;
    return 1;
}

// Test helpers

static i32 outequals(Plt *plt, c16 *expected)
{
    Str16 exp = fromcstr16(expected);
    if (plt->outlen != exp.len) return 0;
    return !__builtin_memcmp(plt->outbuf, exp.data,
                             touz(exp.len * (iz)sizeof(c16)));
}

#include <stdio.h>
#include <stdlib.h>

// Test 1: Empty directory — no output
static i32 test_empty_dir(void)
{
    static u8 mem[1<<20];
    static c16 outbuf[1<<14];

    VDir dirs[] = {
        {u"emptydir", u"\0", 0, 0},
    };
    Plt plt = {
        .dirs  = dirs,  .ndirs  = 1,
        .files = 0,     .nfiles = 0,
        .procs = 0,     .nprocs = 0,
        .outbuf = outbuf, .outlen = 0, .outcap = sizeof(outbuf)/sizeof(*outbuf),
    };

    c16 *argv[] = {u"culprit", u"emptydir"};
    i32 err = app(&plt, 2, argv, mem, sizeof(mem));

    if (err || !outequals(&plt, u"")) {
        printf("FAIL test_empty_dir\n");
        return 1;
    }
    printf("PASS test_empty_dir\n");
    return 0;
}

// Test 2: Directory with dirpids — prints dir + pid lines
static i32 test_dir_with_pids(void)
{
    static u8 mem[1<<20];
    static c16 outbuf[1<<14];

    i32 pids[] = {1234};
    VDir dirs[] = {
        {u"mydir", u"\0", pids, 1},
    };
    VProc procs[] = {
        {u"gdb.exe", 1234},
    };
    Plt plt = {
        .dirs  = dirs,  .ndirs  = 1,
        .files = 0,     .nfiles = 0,
        .procs = procs, .nprocs = 1,
        .outbuf = outbuf, .outlen = 0, .outcap = sizeof(outbuf)/sizeof(*outbuf),
    };

    c16 *argv[] = {u"culprit", u"mydir"};
    i32 err = app(&plt, 2, argv, mem, sizeof(mem));

    c16 *expected = u"mydir\n\t[1234] gdb.exe\n";
    if (err || !outequals(&plt, expected)) {
        printf("FAIL test_dir_with_pids\n");
        return 1;
    }
    printf("PASS test_dir_with_pids\n");
    return 0;
}

// Test 3: Files with pids — binary search narrows to correct file
static i32 test_file_binary_search(void)
{
    static u8 mem[1<<20];
    static c16 outbuf[1<<14];

    i32 fpids[] = {500};
    VDir dirs[] = {
        {u"proj", u"a.txt\0" u"b.txt\0" u"c.txt\0" u"d.txt\0", 0, 0},
    };
    VFile files[] = {
        {u"proj\\a.txt", 0, 0},
        {u"proj\\b.txt", 0, 0},
        {u"proj\\c.txt", fpids, 1},
        {u"proj\\d.txt", 0, 0},
    };
    VProc procs[] = {
        {u"vim.exe", 500},
    };
    Plt plt = {
        .dirs  = dirs,  .ndirs  = 1,
        .files = files, .nfiles = 4,
        .procs = procs, .nprocs = 1,
        .outbuf = outbuf, .outlen = 0, .outcap = sizeof(outbuf)/sizeof(*outbuf),
    };

    c16 *argv[] = {u"culprit", u"proj"};
    i32 err = app(&plt, 2, argv, mem, sizeof(mem));

    c16 *expected = u"proj\\c.txt\n\t[500] vim.exe\n";
    if (err || !outequals(&plt, expected)) {
        printf("FAIL test_file_binary_search (err=%d)\n", err);
        // Print what we got
        printf("  outlen=%td expected_len=%td\n", plt.outlen,
               fromcstr16(expected).len);
        return 1;
    }
    printf("PASS test_file_binary_search\n");
    return 0;
}

// Test 4: Nested directories — stack-based traversal finds deep files
static i32 test_nested_dirs(void)
{
    static u8 mem[1<<20];
    static c16 outbuf[1<<14];

    i32 dpids[] = {100};
    i32 fpids[] = {200};
    VDir dirs[] = {
        {u"root", u"sub\\\0", 0, 0},
        {u"root\\sub", u"deep.txt\0", dpids, 1},
    };
    VFile files[] = {
        {u"root\\sub\\deep.txt", fpids, 1},
    };
    VProc procs[] = {
        {u"app1.exe", 100},
        {u"app2.exe", 200},
    };
    Plt plt = {
        .dirs  = dirs,  .ndirs  = 2,
        .files = files, .nfiles = 1,
        .procs = procs, .nprocs = 2,
        .outbuf = outbuf, .outlen = 0, .outcap = sizeof(outbuf)/sizeof(*outbuf),
    };

    c16 *argv[] = {u"culprit", u"root"};
    i32 err = app(&plt, 2, argv, mem, sizeof(mem));

    // Should find: root\sub (dirpids: 100) and root\sub\deep.txt (filepids: 200)
    // Order: dir results come first (from traversal), then file results (from binary search)
    c16 *expected =
        u"root\\sub\n\t[100] app1.exe\n"
        u"root\\sub\\deep.txt\n\t[200] app2.exe\n";
    if (err || !outequals(&plt, expected)) {
        printf("FAIL test_nested_dirs (err=%d)\n", err);
        printf("  outlen=%td expected_len=%td\n", plt.outlen,
               fromcstr16(expected).len);
        return 1;
    }
    printf("PASS test_nested_dirs\n");
    return 0;
}

// Test 5: File argument (not a directory)
static i32 test_file_arg(void)
{
    static u8 mem[1<<20];
    static c16 outbuf[1<<14];

    i32 fpids[] = {42};
    VFile files[] = {
        {u"single.txt", fpids, 1},
    };
    VProc procs[] = {
        {u"notepad.exe", 42},
    };
    Plt plt = {
        .dirs  = 0,     .ndirs  = 0,
        .files = files, .nfiles = 1,
        .procs = procs, .nprocs = 1,
        .outbuf = outbuf, .outlen = 0, .outcap = sizeof(outbuf)/sizeof(*outbuf),
    };

    c16 *argv[] = {u"culprit", u"single.txt"};
    i32 err = app(&plt, 2, argv, mem, sizeof(mem));

    c16 *expected = u"single.txt\n\t[42] notepad.exe\n";
    if (err || !outequals(&plt, expected)) {
        printf("FAIL test_file_arg (err=%d)\n", err);
        printf("  outlen=%td expected_len=%td\n", plt.outlen,
               fromcstr16(expected).len);
        return 1;
    }
    printf("PASS test_file_arg\n");
    return 0;
}

// Test 6: Multiple pids on one file
static i32 test_multiple_pids(void)
{
    static u8 mem[1<<20];
    static c16 outbuf[1<<14];

    i32 fpids[] = {10, 20};
    VDir dirs[] = {
        {u"d", u"f.c\0", 0, 0},
    };
    VFile files[] = {
        {u"d\\f.c", fpids, 2},
    };
    VProc procs[] = {
        {u"gcc.exe", 10},
        {u"vim.exe", 20},
    };
    Plt plt = {
        .dirs  = dirs,  .ndirs  = 1,
        .files = files, .nfiles = 1,
        .procs = procs, .nprocs = 2,
        .outbuf = outbuf, .outlen = 0, .outcap = sizeof(outbuf)/sizeof(*outbuf),
    };

    c16 *argv[] = {u"culprit", u"d"};
    i32 err = app(&plt, 2, argv, mem, sizeof(mem));

    c16 *expected = u"d\\f.c\n\t[10] gcc.exe\n\t[20] vim.exe\n";
    if (err || !outequals(&plt, expected)) {
        printf("FAIL test_multiple_pids (err=%d)\n", err);
        printf("  outlen=%td expected_len=%td\n", plt.outlen,
               fromcstr16(expected).len);
        return 1;
    }
    printf("PASS test_multiple_pids\n");
    return 0;
}

int main(void)
{
    i32 fails = 0;
    fails += test_empty_dir();
    fails += test_dir_with_pids();
    fails += test_file_binary_search();
    fails += test_nested_dirs();
    fails += test_file_arg();
    fails += test_multiple_pids();
    printf("\n%d failures\n", fails);
    return !!fails;
}
