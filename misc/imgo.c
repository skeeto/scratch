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
// position argument list. Permutation is not supported, and options
// following a positional argument are treated as positional arguments.
//
// This is free and unencumbered software released into the public domain.
#include <string.h>  // memcmp, strcspn

#define IMGOINIT(argc, argv) {argv, 0, argc, 0}

// Match a short/long option. Use zero for either short or long if that
// half does not exist. The long option string must be a literal that
// begins with "--".
#define IMGO(go, s, l) ((s && go.len==1 && *go.opt==s) || \
     (l && go.len==sizeof(l)-1 && !memcmp(l?l:"", go.opt, sizeof(l)-1)))

struct imgo {
    char **argv, *opt;
    int argc, len;
};

// Retrieve the next option, returning non-zero if available. The option
// is indicated by the opt/len fields and is not necessarily null
// terminated. The IMGO macro helps in comparing character and string
// literals with opt/len. When len==1, it is a short option, otherwise
// it is a long option. As a special case, first check if argv is null
// which indicates that the previous option, retained in opt/len, did
// not consume its argument as expected, an error that prevents the
// parser from continuing.
//
// After it returning zero, the argc/argv fields have had all options
// removed as if they never existed, and optional arguments begin at
// argv[1], unless of course argc is zero.
static int imgo(struct imgo *go)
{
    if (go->opt && go->len==1 && *++go->opt) {
        return 1;
    } else if (go->opt && go->len>1 && go->opt[go->len]) {
        return (go->argc=0, go->argv=0, 1);  // unconsumed argument
    } else if (go->argc>=2 && go->argv[1][0]=='-') {
        switch (go->argv[1][1]) {
        case  0 : return 0;
        default : return (go->argc--, go->opt=*++go->argv+1, go->len=1);
        case '-': switch ((go->len = strcspn(go->argv[1], "="))) {
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
    return arg;
}


#if DEMO
// $ cc -DDEMO -o example imgo.c
// $ ./example -abeeed4 -cred foo bar
#include <stdio.h>
#include <stdlib.h>

static const char usage[] =
"usage: example [OPTION]... [ARG]...\n"
"  -a, --amend              Modify previous state\n"
"  -b, --brief              Produce shorter output\n"
"  -c, --color COLOR        Output text color\n"
"  -d, --delay[=SECONDS]    Delay between actions\n"
"  -e, --erase              Clear results (may be repeated)\n";

int main(int argc, char **argv)
{
    char *color = "white";
    int amend=0, brief=0, delay=0, erase=0;

    struct imgo go = IMGOINIT(argc, argv);
    while (imgo(&go)) {
        int missing = 0;
        if (!go.argv) {
            printf("example: %.*s accepts no argument\n", go.len, go.opt);
            return 1;
        } else if (IMGO(go, 'h', "help")) {
            fwrite(usage, sizeof(usage)-1, 1, stdout);
            fflush(stdout);
            return ferror(stdout);
        } else if (IMGO(go, 'a', "--amend")) {
            amend = 1;
        } else if (IMGO(go, 'b', "--brief")) {
            brief = 1;
        } else if (IMGO(go, 'c', "--color")) {
            missing = !(color = imgoarg(&go, 1));
        } else if (IMGO(go, 'd', "--delay")) {
            char *arg = imgoarg(&go, 0);
            delay = arg ? atoi(arg) : 1;
        } else if (IMGO(go, 'e', "--erase")) {
            erase++;
        } else {
            printf("example: unknown option, %s%.*s\n",
                   "-"+(go.len>1), go.len, go.opt);
            fwrite(usage, sizeof(usage)-1, 1, stderr);
            return 1;
        }
        if (missing) {
            printf("example: %s%.*s requires an argument\n",
                   "-"+(go.len>1), go.len, go.opt);
            return 1;
        }
    }

    printf("--amend %d\n", amend);
    printf("--brief %d\n", brief);
    printf("--color %s\n", color);
    printf("--delay %d\n", delay);
    printf("--erase %d\n", erase);
    for (int i = 1; i < go.argc; i++) {
        printf("ARG %s\n", go.argv[i]);
    }
    fflush(stdout);
    return ferror(stdout);
}
#endif
