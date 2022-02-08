// Portable, standalone implementation of moreutils-style sponge
// This is free and unencumbered software released into the public domain.
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *
slurp(FILE *f, size_t *len)
{
    char *buf = 0;
    size_t cap = 1 << 11;

    for (*len = 0;;) {
        cap *= 2;
        if (!cap) {
            free(buf);
            return 0;
        }

        void *tmp = realloc(buf, cap);
        if (!tmp) {
            free(buf);
            return 0;
        }
        buf = tmp;

        size_t in = fread(buf+*len, 1, cap-*len, f);
        *len += in;
        if (in < cap-*len) {
            if (feof(f)) {
                return buf;
            }
            free(buf);
            return 0;
        }
    }
}

static int xoptind;
static int xopterr = 1;
static int xoptopt;
static char *xoptarg;

static int
xgetopt(int argc, char * const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;

    xoptind = xoptind ? xoptind : !!argc;
    arg = argv[xoptind];
    if (arg && strcmp(arg, "--") == 0) {
        xoptind++;
        return -1;
    } else if (!arg || arg[0] != '-' || !isalnum(arg[1])) {
        return -1;
    } else {
        const char *opt = strchr(optstring, arg[optpos]);
        xoptopt = arg[optpos];
        if (!opt) {
            if (xopterr && *optstring != ':')
                fprintf(stderr, "%s: illegal option: %c\n", argv[0], xoptopt);
            return '?';
        } else if (opt[1] == ':') {
            if (arg[optpos + 1]) {
                xoptarg = (char *)arg + optpos + 1;
                xoptind++;
                optpos = 1;
                return xoptopt;
            } else if (argv[xoptind + 1]) {
                xoptarg = (char *)argv[xoptind + 1];
                xoptind += 2;
                optpos = 1;
                return xoptopt;
            } else {
                if (xopterr && *optstring != ':')
                    fprintf(stderr,
                            "%s: option requires an argument: %c\n",
                            argv[0], xoptopt);
                return *optstring == ':' ? ':' : '?';
            }
        } else {
            if (!arg[++optpos]) {
                xoptind++;
                optpos = 1;
            }
            return xoptopt;
        }
    }
}

static void
usage(FILE *f)
{
    fprintf(f, "usage: sponge [-ah] FILE\n");
}

int
main(int argc, char **argv)
{
    int option;
    const char *mode = "wb";

    while ((option = xgetopt(argc, argv, "ah")) != -1) {
        switch (option) {
        case 'a': mode = "ab";   break;
        case 'h': usage(stdout); return 0;
        default : usage(stderr); return 1;
        }
    }

    if (!argv[xoptind] || argv[xoptind+1]) {
        usage(stderr);
        return 1;
    }

    #ifdef _WIN32
    int _setmode(int, int); // set stdin to binary mode
    _setmode(0, 0x8000);
    #endif

    size_t len;
    char *buf = slurp(stdin, &len);
    if (!buf) {
        if (ferror(stdin)) {
            fprintf(stderr, "sponge: read error\n");
            return 1;
        }
        fprintf(stderr, "sponge: out of memory\n");
        return 1;
    }

    char *path = argv[xoptind];
    FILE *f = fopen(path, mode);
    if (!f) {
        fprintf(stderr, "sponge: failed to open file: %s\n", path);
        free(buf);
        return 1;
    }
    if (len && (!fwrite(buf, len, 1, f) || fflush(f))) {
        fprintf(stderr, "sponge: write error: %s\n", path);
        free(buf);
        fclose(f);
        return 1;
    }

    free(buf);
    fclose(f);
    return 0;
}
