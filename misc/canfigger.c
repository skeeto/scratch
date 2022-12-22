// canfigger configuration parser
//
// The canfigger format is like INI, but has no sections. This parser
// matches the idiosyncracies, particularly with whitespace, of the
// original parser, except that there is no distinction between "values"
// and "attributes" (i.e. values beyond the first). Advantages of this
// parser:
// * Simpler, minimalist API: one function, one struct
// * No allocations
// * No libc use
// * 80% smaller implementation
// * Better performance
// * Better license
//
// Ref: https://github.com/andy5995/canfigger
// This is free and unencumbered software released into the public domain.

struct canfigger {
    char *beg, *end;
    enum {CANFIGGER_EOF, CANFIGGER_KEY, CANFIGGER_VAL} type;
};

// Parse the next token, returning the next parser state. The initial
// parser state is zero. The buffer is destroyed as it's parsed, and all
// tokens are null-terminated if, and only if, the buffer itself has a
// null terminator just beyond its end (i.e. not included in len).
static int canfigger(int state, struct canfigger *t, char *buf, int len)
{
    char *beg = buf + (state<0 ? -state : state);
    char *end = buf + len;

    // negative state: parsing values, otherwise parsing keys
    if (state >= 0) {
        while (beg < end) {
            switch (*beg++) {
            case '#':  // comment
                while (beg<end && *beg++!='\n') {}
                continue;
            case '\t': case '\n': case '\v': case '\f': case '\r': case ' ':
                continue;
            default:
                t->type = CANFIGGER_KEY;
                t->beg = beg - 1;
                t->end = beg;
                while (beg < end) {
                    switch (*beg++) {
                    case '=' : *t->end = 0;
                               return buf - beg;
                    case '\n': *t->end = 0;
                               return beg - buf;
                    case '\t':
                    case '\v':
                    case '\f':
                    case '\r':
                    case ' ' : break;
                    default  : t->end = beg;
                    }
                }
                return beg - buf;
            }
        }
        t->type = CANFIGGER_EOF;
        t->beg = t->end = 0;
        return beg - buf;

    } else {
        for (; beg<end && *beg==' '; beg++) {}
        t->type = CANFIGGER_VAL;
        t->beg = t->end = beg;
        while (beg < end) {
            switch (*beg++) {
            case '\n': *t->end = 0;
                       return beg - buf;
            case ',' : *t->end = 0;
                       return buf - beg;
            case '\t':
            case '\v':
            case '\f':
            case '\r':
            case ' ' : break;
            default  : t->end = beg;
            }
        }
        return beg - buf;
    }
}


#if TEST
// $ cc -DTEST -g3 -o test canfigger.c
// $ ./test
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define E(t, s) {s, s+sizeof(s)-1, CANFIGGER_##t}
#define C(s, ...) do {\
        char buf##__LINE__[] = s; \
        check(buf, sizeof(s)-1, __VA_ARGS__); \
    } while (0)

static void check(char *buf, int len, struct canfigger *expect)
{
    for (int state=0, i=0;; i++) {
        struct canfigger t;
        state = canfigger(state, &t, buf, len);
        assert(expect[i].type == t.type);
        if (t.type == CANFIGGER_EOF) {
            break;
        }
        assert(expect[i].end-expect[i].beg == t.end-t.beg);
        assert(!memcmp(t.beg, expect[i].beg, t.end-t.beg));
    }
}

int main(void)
{
    {   char s[] = "";
        struct canfigger e[] = {
            E(EOF, "")
        };
        check(s, sizeof(s)-1, e); }

    {   char s[] = "# empty config";
        struct canfigger e[] = {
            E(EOF, "")
        };
        check(s, sizeof(s)-1, e); }

    {   char s[] = "key=val";
        struct canfigger e[] = {
            E(KEY, "key"),
            E(VAL, "val"),
            E(EOF, "")
        };
        check(s, sizeof(s)-1, e); }

    {   char s[] = "key=value\n";
        struct canfigger e[] = {
            E(KEY, "key"),
            E(VAL, "value"),
            E(EOF, "")
        };
        check(s, sizeof(s)-1, e); }

    {   char s[] = " # comment\nfoo\nbar\n";
        struct canfigger e[] = {
            E(KEY, "foo"),
            E(KEY, "bar"),
            E(EOF, "")
        };
        check(s, sizeof(s)-1, e); }

    {   char s[] = "  k=  a  ,\tb  ,c";
        struct canfigger e[] = {
            E(KEY, "k"),
            E(VAL, "a"),
            E(VAL, "\tb"),
            E(VAL, "c"),
            E(EOF, "")
        };
        check(s, sizeof(s)-1, e); }

    {   char s[] = "foo\nbar=#\nbaz";
        struct canfigger e[] = {
            E(KEY, "foo"),
            E(KEY, "bar"),
            E(VAL, "#"),
            E(KEY, "baz"),
            E(EOF, "")
        };
        check(s, sizeof(s)-1, e); }

    {   char s[] = "key=,,     , \t,\n";
        struct canfigger e[] = {
            E(KEY, "key"),
            E(VAL, ""),
            E(VAL, ""),
            E(VAL, ""),
            E(VAL, ""),
            E(VAL, ""),
            E(EOF, "")
        };
        check(s, sizeof(s)-1, e); }

    puts("all tests pass");
    return 0;
}


#elif FUZZ
//  $ alf-gcc -DFUZZ -m32 -g3 -fsanitize=address,undefined -g3 canfigger.c
//  $ mkdir -p i && echo >i/empty
//  $ afl-fuzz -m800 -ii -oo ./a.out
#include <stdio.h>

int main(void)
{
    static char buf[1<<20];
    int len = fread(buf, 1, sizeof(buf)-1, stdin);
    buf[len] = 0;
    for (int state = 0;;) {
        struct canfigger t;
        state = canfigger(state, &t, buf, len);
        switch (t.type) {
        case CANFIGGER_EOF:
            fflush(stdout);
            return ferror(stdout);
        case CANFIGGER_VAL:
            putchar('\t'); // fallthrough
        case CANFIGGER_KEY:
            printf("%d:%s\n", (int)(t.end-t.beg), t.beg);
            break;
        }
    }
}
#endif
