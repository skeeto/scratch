// INI to hash trie parser
//
// A little experiment to parse an INI file into a hash trie for key
// lookups. The trie is internal, hidden from the caller, and only a
// simple, traditional C interface is presented. All allocations are
// made in the provided heap.
//
//   int   cap   = 1<<20;
//   void *heap  = malloc(cap);
//   char  txt[] = "[example]\nhello = world";
//   ini  *conf  = ini_load(txt, sizeof(txt)-1, heap, heap?cap:0);
//   char *world = ini_get(conf, "example", "hello");  // => "world"
//   free(heap);
//
// This is free and unencumbered software released into the public domain.


// Interface

typedef struct ini ini;

// Parse INI-formatted text into an internal representation. Allocations
// come only out of the provided, pointer-aligned heap. All inputs are
// valid and parsing errors are impossible. Returns null if the heap is
// too small. The returned object has pointers into the input buffer.
//
// Leading and trailing whitespace is stripped from unquoted values, and
// quotes have no escaping. Comments are unsupported, but they generally
// just work anyway.
ini *ini_load(char *buf, int len, void *heap, int cap);

// Lookup the value for a section/key from the parsed INI. Returns null
// if nothing was found. The ini object may be null, in which case all
// lookups fail.
char *ini_get(ini *, char *section, char *key);


// Implementation (freestanding)

#define assert(c)     while (!(c)) *(volatile int *)0 = 0
#define new(a, t, n)  (t *)alloc(a, sizeof(t)*n)

typedef struct {
    char *beg;
    char *end;
} arena;

static void *alloc(arena *a, int size)
{
    int padding = -size & (sizeof(void *) - 1);
    if (size > a->end - a->beg - padding) {
        return 0;  // out of memory
    }
    char *p = a->beg;
    a->beg += size + padding;
    for (int i = 0; i < size; i++) {
        p[i] = 0;
    }
    return p;
}

typedef struct {
    char *data;
    int   len;
} str;

static char *tocstr(str s, arena *perm)
{
    char *r = new(perm, char, s.len+1);
    if (r) {
        for (int i = 0; i < s.len; i++) {
            r[i] = s.data[i];
        }
    }
    return r;
}

static str fromcstr(char *s)
{
    str r = {0};
    r.data = s;
    for (; r.data[r.len]; r.len++) {}
    return r;
}

static _Bool equals(str a, str b)
{
    if (a.len != b.len) {
        return 0;
    }
    for (int i = 0; i < a.len; i++) {
        if (a.data[i] != b.data[i]) {
            return 0;
        }
    }
    return 1;
}

static unsigned long hash(str s, unsigned long h)
{
    for (int i = 0; i < s.len; i++) {
        h ^= s.data[i];
        h *= 3226618127u;
    }
    return h;
}

static str cuthead(str s, int len)
{
    assert(len >= 0);
    assert(len <= s.len);
    s.data += len;
    s.len -= len;
    return s;
}

static str takehead(str s, int len)
{
    assert(len >= 0);
    assert(len <= s.len);
    s.len = len;
    return s;
}

static _Bool space(char c)
{
    return c=='\t' || c=='\r' || c==' ';
}

static str skipspace(str s)
{
    assert(s.len >= 0);
    for (; s.len && space(*s.data); s.data++, s.len--) {}
    return s;
}

static str trimspace(str s)
{
    assert(s.len >= 0);
    for (; s.len && space(s.data[s.len-1]); s.len--) {}
    return s;
}

typedef enum {
    tok_EOF,
    tok_EOL,
    tok_LB,
    tok_RB,
    tok_EQ,
    tok_TEXT,
} toktype;

typedef struct {
    toktype type;
    str     value;
    str     input;
} token;

static token next(str input)
{
    token t = {0};

    input = skipspace(input);
    if (!input.len) {
        t.type = tok_EOF;
        t.value = input;
        t.input = input;
        return t;
    }

    switch (*input.data) {
    case '\n':
        t.type = tok_EOL;
        t.value = takehead(input, 1);
        t.input = cuthead(input, 1);
        return t;

    case '[':
        t.type = tok_LB;
        t.value = takehead(input, 1);
        t.input = cuthead(input, 1);
        return t;

    case ']':
        t.type = tok_RB;
        t.value = takehead(input, 1);
        t.input = cuthead(input, 1);
        return t;

    case '=':
        t.type = tok_EQ;
        t.value = takehead(input, 1);
        t.input = cuthead(input, 1);
        return t;

    case '"':
        t.type = tok_TEXT;
        input = cuthead(input, 1);
        int len = 0;
        for (; len<input.len && input.data[len]!='\n'; len++) {
            switch (input.data[len]) {
            case '"':
                t.value = takehead(input, len);
                t.input = cuthead(input, len+1);
                return t;
            }
        }
        t.value = takehead(input, len);
        t.input = cuthead(input, len);
        return t;
    }

    int len = 1;
    for (; len < input.len; len++) {
        char c = input.data[len];
        if (c=='\n' || c=='[' || c==']' || c=='=') {
            break;
        }
    }
    t.type = tok_TEXT;
    t.value = takehead(input, len);
    t.value = trimspace(t.value);
    t.input = cuthead(input, len);
    return t;
}

struct ini {
    ini  *child[2];
    str   section;
    str   key;
    char *value;
};

static char **upsert(ini **m, str section, str key, arena *perm)
{
    for (unsigned long h = hash(section, -hash(key, -1)); *m; h <<= 1) {
        if (equals((*m)->section, section) && equals((*m)->key, key)) {
            return &(*m)->value;
        }
        m = &(*m)->child[(h>>31)&1];
    }
    *m = perm ? new(perm, ini, 1) : 0;
    if (!*m) {
        return 0;
    }
    (*m)->section = section;
    (*m)->key = key;
    return &(*m)->value;
}

ini *ini_load(char *buf, int len, void *heap, int cap)
{
    assert(len >= 0);
    assert(cap >= 0);

    char dummy;
    if (!heap) {
        assert(!cap);
        heap = &dummy;  // no null arenas
    }

    arena perm[1] = {0};
    perm->beg = heap;
    perm->end = perm->beg + cap;

    ini *r = 0;

    token t = {0};
    t.input.data = buf;
    t.input.len = len;

    str section = {0};
    for (;;) {
        str key = {0};
        t = next(t.input);
        switch (t.type) {
        case tok_EOF:
            return r ? r : new(perm, ini, 1);

        case tok_EOL:
            continue;

        case tok_LB:
            t = next(t.input);
            if (t.type != tok_TEXT) break;
            str name = t.value;
            t = next(t.input);
            if (t.type != tok_RB) break;
            section = name;
            break;  // discard remaining line

        case tok_RB:
            break;

        case tok_TEXT:
            key = t.value;
            t = next(t.input);
            if (t.type != tok_EQ) break;
            // fallthrough
        case tok_EQ:
            t = next(t.input);
            if (t.type != tok_TEXT) break;
            char **value = upsert(&r, section, key, perm);
            if (!value) {
                return 0;  // out of memory
            }
            *value = tocstr(t.value, perm);
            if (!*value) {
                return 0;  // out of memory
            }
        }

        // Consume remaining line
        if (t.type != tok_EOL) {
            for (;;) {
                t = next(t.input);
                if (t.type==tok_EOF || t.type==tok_EOL) {
                    break;
                }
            }
        }
    }
}

char *ini_get(ini *ini, char *section, char *key)
{
    assert(section);
    assert(key);
    char **v = upsert(&ini, fromcstr(section), fromcstr(key), 0);
    return v ? *v : 0;
}


// Test

#ifdef _WIN32
// $ cc -nostartfiles -o ini-hashtrie.exe ini-hashtrie.c
// $ gdb ./ini-hashtrie
// (gdb) break check
// (gdb) commands
// > silent
// > print c
// > continue
// > end
// (gdb) r <example.ini
#include <stddef.h>
#define W32(r) __declspec(dllimport) r __stdcall
W32(void *) VirtualAlloc(void *, size_t, int, int);
W32(int)    ReadFile(void *, void *, int, int *, void *);
W32(void *) GetStdHandle(int);
W32(void)   ExitProcess(int);

static int parseint(char *s)
{
    if (!s) return -1;
    int v = 0;
    for (; (unsigned)*s-'0'<=9; s++) {
        v = v*10u + *s - '0';
    }
    return v;
}

typedef struct {
    char *name;
    char *organization;
    char *server;
    int   port;
    char *file;
} config;

static config test(void *heap, int cap)
{
    void *stdin = GetStdHandle(-10);
    char *buf = heap;
    int len;
    ReadFile(stdin, buf, cap, &len, 0);

    int pad = -len & 15;
    ini *ini = ini_load(buf, len, buf+len+pad, cap-len-pad);

    // Parses the example currently on Wikipedia
    config c = {0};
    c.name =          ini_get(ini, "owner", "name");
    c.organization =  ini_get(ini, "owner", "organization");
    c.server =        ini_get(ini, "database", "server");
    c.port = parseint(ini_get(ini, "database", "port"));
    c.file =          ini_get(ini, "database", "file");
    return c;
}

static void check(config c) { (void)c; }  // break and print in debugger

void mainCRTStartup(void)
{
    int cap = 1<<20;
    char *heap = VirtualAlloc(0, cap, 0x3000, 4);
    config c = test(heap, cap);
    check(c);
    ExitProcess(0);
}
#endif


// Fuzzing

#ifdef __AFL_COMPILER
// $ afl-gcc-fast -g3 -fsanitize=address,undefined ini-hashtrie.c
// $ mkdir i
// $ printf '[a]\nhello = "world"' >i/ini
// $ afl-fuzz -ii -oo ./a.out
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(void)
{
    __AFL_INIT();
    int cap = 1<<12;
    char *heap = malloc(cap);
    char *src = 0;
    unsigned char *buf  = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        src = realloc(src, len);
        memcpy(src, buf, len);
        ini_load(src, len, heap, cap);
    }
}
#endif
