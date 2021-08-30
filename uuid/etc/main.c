#include "../uuidgen.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int optind = 1;
static int opterr = 1;
static int optopt;
static char *optarg;

static int
xgetopt(int argc, char * const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;
    (void)argc;

    /* Reset? */
    if (optind == 0) {
        optind = 1;
        optpos = 1;
    }

    arg = argv[optind];
    if (arg && strcmp(arg, "--") == 0) {
        optind++;
        return -1;
    } else if (!arg || arg[0] != '-' || !isalnum(arg[1])) {
        return -1;
    } else {
        const char *opt = strchr(optstring, arg[optpos]);
        optopt = arg[optpos];
        if (!opt) {
            if (opterr && *optstring != ':')
                fprintf(stderr, "%s: illegal option: %c\n", argv[0], optopt);
            return '?';
        } else if (opt[1] == ':') {
            if (arg[optpos + 1]) {
                optarg = (char *)arg + optpos + 1;
                optind++;
                optpos = 1;
                return optopt;
            } else if (argv[optind + 1]) {
                optarg = (char *)argv[optind + 1];
                optind += 2;
                optpos = 1;
                return optopt;
            } else {
                if (opterr && *optstring != ':')
                    fprintf(stderr,
                            "%s: option requires an argument: %c\n",
                            argv[0], optopt);
                return *optstring == ':' ? ':' : '?';
            }
        } else {
            if (!arg[++optpos]) {
                optind++;
                optpos = 1;
            }
            return optopt;
        }
    }
}

static void
usage(FILE *f)
{
    fputs("usage: uuidgen [-h] [-n N]\n", f);
}

int
main(int argc, char *argv[])
{
    long n = 1;

    int option;
    while ((option = xgetopt(argc, argv, "hn:")) != -1) {
        char *end;
        switch (option) {
        case 'h': usage(stdout);
                  return 0;
        case 'n': errno = 0;
                  n = strtol(optarg, &end, 10);
                  if (errno || *end || n < 0) {
                      fprintf(stderr, "%s: invalid -n, %s\n", argv[0], optarg);
                      return 1;
                  }
                  break;
        default: usage(stderr);
                 return 1;
        }
    }

    struct uuidgen g = UUIDGEN_INIT;
    char buf[37] = {0};
    for (long i = 0; i < n; i++) {
        uuidgen(&g, buf);
        puts(buf);
    }
}
