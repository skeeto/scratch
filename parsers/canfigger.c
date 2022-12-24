// canfigger configuration parser
//
// The canfigger format is like INI, but has no sections. This parser
// matches the idiosyncracies, particularly with whitespace, of the
// original parser, except that there is no distinction between "values"
// and "attributes" (i.e. values beyond the first).
//
// Advantages:
// * Simpler, minimalist API: one function, one struct
// * No allocations
// * No libc use
// * No practical maximum length for keys or values
// * 80% smaller implementation
// * Better performance
// * Better license
// Disadvantages:
// * Hardcoded delimiter (comma)
// * Entire raw config must be loaded at once
//
// Ref: https://github.com/andy5995/canfigger
// This is free and unencumbered software released into the public domain.

struct canfigger {
    char *beg, *end;
    enum {CANFIGGER_EOF, CANFIGGER_KEY, CANFIGGER_VAL} type;
};

// Parse the next token, returning the next parser state. The initial
// parser state is zero. If the input has a spare byte just beyond its
// length, such as a null terminator, it's always safe to write a zero
// into the token end pointer to null terminate it.
static int canfigger(int state, struct canfigger *t, const char *buf, int len)
{
    char *beg = (char *)buf + (state<0 ? -state : state);
    char *end = (char *)buf + len;

    // negative state: parsing values, otherwise parsing keys
    if (state >= 0) {
        while (beg < end) {
            switch (*beg++) {
            case '#':  // comment
                while (beg<end && *beg++!='\n') {}
                break;
            case '\t': case '\n': case '\v': case '\f': case '\r': case ' ':
                break;
            default:
                t->type = CANFIGGER_KEY;
                t->beg = beg - 1;
                t->end = beg;
                while (beg < end) {
                    switch (*beg++) {
                    case '=' : return buf - beg;
                    case '\n': return beg - buf;
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
            case '\n': return beg - buf;
            case ',' : return buf - beg;
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
            *t.end = 0;
            printf("%d:%s\n", (int)(t.end-t.beg), t.beg);
            break;
        }
    }
}


#elif EXAMPLE1
// Sums values per key, demonstrating peek/back-off when reading values.
//  $ cc -DEXAMPLE1 -o example canfigger.c
//  $ printf 'a=1,2,3\nb=4,5,6,-7' | ./example
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    static char buf[1<<20];
    int len = fread(buf, 1, sizeof(buf)-1, stdin);
    for (int state = 0;;) {
        long long sum = 0;
        struct canfigger key, val;
        state = canfigger(state, &key, buf, len);
        switch (key.type) {
        case CANFIGGER_EOF:
            fflush(stdout);
            return ferror(stdout);
        case CANFIGGER_VAL:
            abort();  // impossible
        case CANFIGGER_KEY:
            // Read values until a non-value appears, then discard that
            // last parser state so that it's re-read in the outer loop.
            for (int next = state;; state = next) {
                next = canfigger(state, &val, buf, len);
                if (val.type != CANFIGGER_VAL) {
                    break;
                }
                *val.end = 0;  // for atoi()
                sum += (unsigned long long)atoi(val.beg);
            }
            printf("%.*s %lld\n", (int)(key.end-key.beg), key.beg, sum);
        }
    }
}


#elif EXAMPLE2
// Sums values per key, demonstrating a state machine that does not
// require peek/back-off.
//  $ cc -DEXAMPLE2 -o example canfigger.c
//  $ printf 'a=1,2,3\nb=4,5,6,-7' | ./example
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    long long sum;
    static char buf[1<<20];
    int len = fread(buf, 1, sizeof(buf)-1, stdin);
    struct canfigger tok, key = {0, 0, CANFIGGER_KEY};
    for (int state = 0; key.type == CANFIGGER_KEY;) {
        state = canfigger(state, &tok, buf, len);
        switch (tok.type) {
        case CANFIGGER_EOF:
        case CANFIGGER_KEY:
            if (key.beg) {
                fwrite(key.beg, key.end-key.beg, 1, stdout);
                printf(" %lld\n", sum);
            }
            sum = 0;
            key = tok;
            break;
        case CANFIGGER_VAL:
            *tok.end = 0;  // for atoi()
            sum += (unsigned long long)atoi(tok.beg);
        }
    }
    fflush(stdout);
    return ferror(stdout);
}
#endif
