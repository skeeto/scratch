// Count character information (BOM and types)
//
// Output columns: size NULs TABs LFs CRLFs BOM name
//
//   $ cc -DCMD -O3 -s -o chars chars.c
//   $ ./chars chars chars.c chars.dot
//
//   $ cc -DTEST -fsanitize=address,undefined -o tests chars.c
//   $ ./tests
//
// Ref: https://github.com/jftuga/chars
// Ref: https://old.reddit.com/r/golang/comments/s64jye/
//
// This is free and unencumbered software released into the public domain.

#define CHARS_INIT  {0, 0, 0, 0, 0, 0, 2}
#define CHARS_TOTAL(s) ((s).misc+(s).nul+(s).tab+(s).lf+(s).crlf)

struct chars {
    unsigned long long misc;
    unsigned long long nul;
    unsigned long long tab;
    unsigned long long lf;
    unsigned long long crlf;
    enum { CHARS_NOBOM, CHARS_BOM8, CHARS_BOM16LE, CHARS_BOM16BE } bom;
    int state;
};

// Accumulate another byte into the tabulation. Total number of bytes
// consumed is the sum of the five counts.
static void
chars_push(struct chars *c, int b)
{
    static const unsigned char t[2][256] = {
        { [0x00] = 1, [0x09] = 2, [0x0a] = 3 },
        { [0x00] = 1, [0x09] = 2, [0x0a] = 4 },
    };
    b &= 0xff;

    // A state machine, initally at state 2. For the first few inputs it
    // hops around various states trying to parse a BOM, but quickly
    // settles into states 0 and 1. These final states run the same code
    // and are differentiated only by table lookups, i.e. there is no
    // branching within these two states. Branching on the state is very
    // predictable after the initial input.
    switch (c->state) {
    case 0:
    case 1: (&c->misc)[t[c->state][b]]++;
            c->state = b == 0x0d;
            break;
    case 2: switch (b) {
            case 0x0d: c->state = 1; break;
            case 0xef: c->state = 3; break;
            case 0xfe: c->state = 4; break;
            case 0xff: c->state = 5; break;
            default  : c->state = 0; break;
            } (&c->misc)[t[0][b]]++; break;
    case 3: switch (b) {
            case 0x0d: c->state = 1; break;
            case 0xbb: c->state = 6; break;
            default  : c->state = 0; break;
            } (&c->misc)[t[0][b]]++; break;
    case 4: switch (b) {
            case 0x0d: c->state = 1; break;
            case 0xff: c->bom = CHARS_BOM16BE; // fallthrough
            default  : c->state = 0; break;
            } (&c->misc)[t[0][b]]++; break;
    case 5: switch (b) {
            case 0x0d: c->state = 1; break;
            case 0xfe: c->bom = CHARS_BOM16LE; // fallthrough
            default  : c->state = 0; break;
            } (&c->misc)[t[0][b]]++; break;
    case 6: switch (b) {
            case 0x0d: c->state = 1; break;
            case 0xbf: c->bom = CHARS_BOM8;    // fallthrough
            default  : c->state = 0; break;
            } (&c->misc)[t[0][b]]++; break;
    }
}


#if defined(CMD)
#include <stdio.h>

static int
process(struct chars *c, FILE *f)
{
    *c = (struct chars)CHARS_INIT;
    for (unsigned char buf[1<<14];;) {
        int n = fread(buf, 1, sizeof(buf), f);
        if (!n) {
            if (ferror(f)) {
                return 0;
            }
            return 1;
        }
        for (int i = 0; i < n; i++) {
            chars_push(c, buf[i]);
        }
    }
}

static int
print(struct chars *c, const char *name, int n)
{
    static const char bom[][9] = {
        [CHARS_NOBOM]   = {"(no-BOM)"},
        [CHARS_BOM8]    = {"UTF-8"},
        [CHARS_BOM16LE] = {"UTF-16LE"},
        [CHARS_BOM16BE] = {"UTF-16BE"},
    };
    return printf("%*llu %*llu %*llu %*llu %*llu %9s %s\n",
                  n, CHARS_TOTAL(*c),
                  n, c->nul, n, c->tab,
                  n, c->lf,  n, c->crlf,
                  bom[c->bom], name) > 0;
}

int
main(int argc, char **argv)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    int width = 10;
    struct chars c[1];

    if (argc <= 1) {
        if (!process(c, stdin)) {
            fputs("chars: read error: <stdin>\n", stderr);
            return 1;
        }
        print(c, "<stdin>", width);
    }

    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            fprintf(stderr, "chars: cannot open: %s\n", argv[1]);
            return 1;
        }
        if (!process(c, f)) {
            fclose(f);
            fprintf(stderr, "chars: read error: %s\n", argv[1]);
            return 1;
        }
        fclose(f);
        if (!print(c, argv[i], width)) {
            break;  // write error, stop early
        }
    }

    fflush(stdout);
    if (ferror(stdout)) {
        fputs("chars: write error\n", stderr);
        return 1;
    }
}


#elif defined(TEST)
#include <stdio.h>

int
main(void)
{
    static const struct {
        char input[8];
        struct chars want;
    } tests[] = {
        {"\xef\xbb\xbfhello",
            {.lf=0, .crlf=0, .nul=0, .tab=0, .bom=CHARS_BOM8}},
        {"\xff\xfe\thi\t\r\n",
            {.lf=0, .crlf=1, .nul=0, .tab=2, .bom=CHARS_BOM16LE}},
        {"\xfe\xff\x00hi\r\n\n",
            {.lf=1, .crlf=1, .nul=1, .tab=0, .bom=CHARS_BOM16BE}},
        {"\xfe\xfe\r\n\n\r",
            {.lf=1, .crlf=1, .nul=2, .tab=0, .bom=0}},
        {"\xff\xff",
            {.lf=0, .crlf=0, .nul=6, .tab=0, .bom=0}},
        {"\xef\xbb\n",
            {.lf=1, .crlf=0, .nul=5, .tab=0, .bom=0}},
        {"\xfe\xbb\xbf",
            {.lf=0, .crlf=0, .nul=5, .tab=0, .bom=0}},
    };
    int ntests = sizeof(tests) / sizeof(*tests);

    int fails = 0;
    for (int i = 0; i < ntests; i++) {
        struct chars s = CHARS_INIT;
        for (int j = 0; j < 8; j++) {
            chars_push(&s, tests[i].input[j]);
        }

        if (tests[i].want.lf != s.lf) {
            fails++;
            printf("FAIL: (%d) LF: want %llu, got %llu\n",
                   i, tests[i].want.lf, s.lf);
        }
        if (tests[i].want.crlf != s.crlf) {
            fails++;
            printf("FAIL: (%d) CRLF: want %llu, got %llu\n",
                   i, tests[i].want.crlf, s.crlf);
        }
        if (tests[i].want.nul != s.nul) {
            fails++;
            printf("FAIL: (%d) NUL: want %llu, got %llu\n",
                   i, tests[i].want.nul, s.nul);
        }
        if (tests[i].want.tab != s.tab) {
            fails++;
            printf("FAIL: (%d) TAB: want %llu, got %llu\n",
                   i, tests[i].want.tab, s.tab);
        }
        if (sizeof(tests[i].input) != CHARS_TOTAL(s)) {
            fails++;
            printf("FAIL: (%d) Misc: want %llu, got %llu\n",
                   i, tests[i].want.misc, s.misc);
        }
        if (tests[i].want.bom != s.bom) {
            fails++;
            printf("FAIL: (%d) BOM: want %x, got %x\n",
                   i, tests[i].want.bom, s.bom);
        }
    }

    if (!fails) {
        puts("All tests pass.");
    }
    return !!fails;
}
#endif
