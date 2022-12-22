// imgo -- Immediate Mode Getopt
//
// A short and long option parser, including optional option arguments,
// in under 40 lines of code.
//
// Instead of a static, "retained" table of valid options, discovered
// options are passed to the caller who either consumes or rejects them.
// That is, the table is built into the structure of the code. The IMGO
// macro assists in constructing this code using character and string
// literals.
//
// Per convention, "--" halts option parsing and is not included in the
// positional argument list. Permutation is not supported, and options
// following a positional argument are treated as positional arguments.
//
// This is free and unencumbered software released into the public domain.
#include <string.h>  // memcmp, strcspn

#define IMGOINIT(argc, argv) {argv, 0, argc, 0, 0}

// Match a short/long option. Use zero for either short or long if that
// half does not exist. The long option string must be a literal that
// begins with "--".
#define IMGO(go, s, l) ((s && go.len==1 && *go.opt==s) || \
     (l && go.len==sizeof(l)-1 && !memcmp(l?l:"", go.opt, sizeof(l)-1)))

struct imgo {
    char **argv, *opt;
    int argc, len;
    enum {IMGOTOOMANY=1, IMGOMISSING=2, IMGOINVALID=3} err;
};

// Retrieve the next option, returning non-zero if available. The option
// is indicated by the opt/len fields and is not necessarily null
// terminated. The IMGO macro helps in comparing character and string
// literals with opt/len. When len==1, it is a short option, otherwise
// it is a long option.
//
// If err is non-zero then previous option, retained in opt/len, had an
// error. This may be a missing option argument or an unconsumed option
// argument. Parsing may continue by clearing the error, and in the case
// of IMGOTOOMANY, consuming the argument. IMGOINVALID is defined for
// convenience but never returned.
//
// After returning zero, the argc/argv fields have had all options
// removed as if they never existed, and optional arguments begin at
// argv[1], unless of course argc < 2.
static int imgo(struct imgo *go)
{
    if (go->err || (go->opt && go->len==1 && *++go->opt)) {
        return 1;
    } else if (go->opt && go->len>1 && go->opt[go->len]) {
        return go->err = IMGOTOOMANY;
    } else if (go->argc>=2 && go->argv[1][0]=='-') {
        switch (go->argv[1][1]) {
        case  0 : return 0;
        default : return (go->argc--, go->opt=*++go->argv+1, go->len=1);
        case '-': switch (go->len = strcspn(go->argv[1], "=")) {
                  case  2: return (go->argv++, go->argc--, 0);  // --
                  default: return (go->opt=*++go->argv, go->argc--);
                  }
        }
    }
    return 0;
}

// Retrieve the option argument, or null if none was provided. The
// opt/len is untouched on null return so that it can be used in error
// reporting (missing option argument).
static char *imgoarg(struct imgo *go, int required)
{
    char *arg = 0;
    if (go->opt[go->len]) {
        arg = go->opt + go->len + (go->len>1);
        go->opt = 0;
    } else if (required && go->argc>=2) {
        arg = (go->argc--, *++go->argv);
    }
    go->err = required && !arg ? IMGOMISSING : 0;
    return arg;
}


#if DEMO
// $ cc -DDEMO -o demo imgo.c
// $ ./demo -abeeed4 -cred foo bar
#include <stdio.h>
#include <stdlib.h>

static const char *errmsg[] = {
    [IMGOTOOMANY] = "does not allow an argument",
    [IMGOMISSING] = "requires an argument",
    [IMGOINVALID] = "unrecognized",
};
static const char usage[] =
"usage: demo [OPTION]... [ARG]...\n"
"  -a, --amend              Modify previous state\n"
"  -b, --brief              Produce shorter output\n"
"  -c, --color[=COLOR]      Output text color\n"
"  -d, --delay SECONDS      Delay between actions\n"
"  -e, --erase              Clear results (may be repeated)\n";

int main(int argc, char **argv)
{
    char *color=0;
    int amend=0, brief=0, delay=0, erase=0;

    struct imgo go = IMGOINIT(argc, argv);
    while (!go.err && imgo(&go)) {
        if (IMGO(go, 'h', "--help")) {
            fwrite(usage, sizeof(usage)-1, 1, stdout);
            fflush(stdout);
            return ferror(stdout);
        } else if (IMGO(go, 'a', "--amend")) {
            amend = 1;
        } else if (IMGO(go, 'b', "--brief")) {
            brief = 1;
        } else if (IMGO(go, 'c', "--color")) {
            color = imgoarg(&go, 0);
            color = color ? color : "(enabled)";
        } else if (IMGO(go, 'd', "--delay")) {
            char *arg = imgoarg(&go, 1);
            if (arg) {
                delay = atoi(arg);
            }
        } else if (IMGO(go, 'e', "--erase")) {
            erase++;
        } else {
            go.err = IMGOINVALID;
        }
    }
    if (go.err) {
        fprintf(stderr, "demo: option '%s%.*s' %s\n",
                "-"+(go.len>1), go.len, go.opt, errmsg[go.err]);
        fwrite(usage, sizeof(usage)-1, 1, stderr);
        return 1;
    }

    printf("--amend %d\n", amend);
    printf("--brief %d\n", brief);
    printf("--color %s\n", color ? color : "(disabled)");
    printf("--delay %d\n", delay);
    printf("--erase %d\n", erase);
    for (int i = 1; i < go.argc; i++) {
        printf("ARG %s\n", go.argv[i]);
    }
    fflush(stdout);
    return ferror(stdout);
}
#endif


#ifdef TEST
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(c) if (!(c)) *(volatile int *)0 = 0

int main(void)
{
    struct config {
        int   amend;
        int   brief;
        char *color;
        int   delay;
        int   erase;
    };
    struct {
        char *argv[8];
        struct config conf;
        char *args[8];
        int err;
    } t[] = {
        {
            {"", "--", "foobar", 0},
            {0, 0, 0, 0, 0},
            {"foobar", 0},
            0
        },
        {
            {"", "-a", "-b", "-c", "-d", "10", "-e", 0},
            {1, 1, "", 10, 1},
            {0},
            0
        },
        {
            {
                "",
                "--amend",
                "--brief",
                "--color",
                "--delay",
                "10",
                "--erase",
                0
            },
            {1, 1, "", 10, 1},
            {0},
            0
        },
        {
            {"", "-a", "-b", "-cred", "-d", "10", "-e", 0},
            {1, 1, "red", 10, 1},
            {0},
            0
        },
        {
            {"", "-abcblue", "-d10", "foobar", 0},
            {1, 1, "blue", 10, 0},
            {"foobar", 0},
            0
        },
        {
            {"", "--color=red", "-d", "10", "--", "foobar", 0},
            {0, 0, "red", 10, 0},
            {"foobar", 0},
            0
        },
        {
            {"", "-eeeeee", 0},
            {0, 0, 0, 0, 6},
            {0},
            0
        },
        {
            {"", "--amend=abc", 0},
            {0, 0, 0, 0, 0},
            {0},
            IMGOTOOMANY
        },
        {
            {"", "--delay", 0},
            {0, 0, 0, 0, 0},
            {0},
            IMGOMISSING
        },
        {
            {"", "--foo", "bar", 0},
            {0, 0, 0, 0, 0},
            {"--foo", "bar", 0},
            IMGOINVALID
        },
        {
            {"", "-x", 0},
            {0, 0, 0, 0, 0},
            {"-x", 0},
            IMGOINVALID
        },
        {
            {"", "-", 0},
            {0, 0, 0, 0, 0},
            {"-", 0},
            0
        },
        {
            {"", "-e", "foo", "bar", "baz", "-a", "quux", 0},
            {0, 0, 0, 0, 1},
            {"foo", "bar", "baz", "-a", "quux", 0},
            0
        }
    };
    int ntests = sizeof(t) / sizeof(*t);

    for (int i = 0; i < ntests; i++) {
        int argc = 0;
        for (char **arg = t[i].argv; *arg; arg++, argc++) {}

        struct config c = {0, 0, 0, 0, 0};
        struct imgo go = IMGOINIT(argc, t[i].argv);
        while (!go.err && imgo(&go)) {
            if (IMGO(go, 'a', "--amend")) {
                c.amend = 1;
            } else if (IMGO(go, 'b', "--brief")) {
                c.brief = 1;
            } else if (IMGO(go, 'c', "--color")) {
                c.color = imgoarg(&go, 0);
                c.color = c.color ? c.color : "";
            } else if (IMGO(go, 'd', "--delay")) {
                char *arg = imgoarg(&go, 1);
                if (arg) {
                    c.delay = atoi(arg);
                }
            } else if (IMGO(go, 'e', "--erase")) {
                c.erase++;
            } else {
                go.err = IMGOINVALID;
            }
        }

        ASSERT((int)go.err == t[i].err);
        for (int a = 1; !go.err && a<go.argc; a++) {
            ASSERT(t[i].args[a-1]);
            ASSERT(!strcmp(t[i].args[a-1], go.argv[a]));
        }
    }
    puts("all tests pass");
}
#endif
