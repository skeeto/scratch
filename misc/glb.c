/* GLB extractor for Raptor: Call of the Shadows
 * Written in ANSI C90 and supports all operating systems, including MS-DOS.
 *
 * Usage:
 *   $ cc -o glb glb.c
 *   $ ./glb <FILE0000.GLB -x0
 *
 * Ref: https://moddingwiki.shikadi.net/wiki/GLB_Format_(Raptor)
 * This is free and unencumbered software released into the public domain.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct hdr {
    long flags, off, len;
    char filename[16];
};

static char errbuf[64];

/* Decrypt a buffer in place. Returns the state such that decryption can
 * continue with more input. Use zero for the initial state. Except for the
 * final call, length must be divisible by 8.
 */
static int
decrypt(unsigned char *buf, long len, int state)
{
    static const unsigned char key[8] = "dihjy~te";
    long i;
    for (i = 0; i < len; i++) {
        int t = buf[i];
        buf[i] = t - key[i&7] - state;
        state = t - '2';
    }
    return state;
}

static unsigned long
load_u32le(unsigned char *buf)
{
    return (unsigned long)buf[0] <<  0 | (unsigned long)buf[1] <<  8 |
           (unsigned long)buf[2] << 16 | (unsigned long)buf[3] << 24;

}

/* Parse the header at the current file position and validate it. Returns a
 * descriptive error string, or null on success.
 */
static const char *
load_hdr(struct hdr *hdr, long i)
{
    unsigned char buf[28];

    if (!fread(buf, 28, 1, stdin)) {
        sprintf(errbuf, "file #%ld: unexpected end of input", i);
        return errbuf;
    }

    decrypt(buf, 28, 0);
    hdr->flags = load_u32le(buf+0);
    hdr->off   = load_u32le(buf+4);
    hdr->len   = load_u32le(buf+8);
    memcpy(hdr->filename, buf+12, 16);

    if (hdr->len < 0 || hdr->off < 0 || buf[27]) {
        sprintf(errbuf, "file #%ld: corrupted entry header", i);
        return errbuf;
    } else if (hdr->flags & ~1L) {
        sprintf(errbuf, "file #%ld: invalid flags: %08lx", i, hdr->flags);
        return errbuf;
    }

    return 0;
}

struct xgetopt { char *optarg; int optind, optopt, optpos; };

static int
xgetopt(struct xgetopt *x, int argc, char **argv, const char *optstring)
{
    char *arg = argv[!x->optind ? (x->optind += !!argc) : x->optind];
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

static const char *
cmd_list(long nfiles)
{
    long i;
    const char *err;
    struct hdr hdr;

    for (i = 0; i < nfiles; i++) {
        err = load_hdr(&hdr, i);
        if (err) {
            return err;
        }

        printf("%-4ld %-16s%c %11ld\n",
               i, hdr.filename, hdr.flags ? 'E' : 'P', hdr.len);
    }

    return 0;
}

static const char *
cmd_extract(long entry)
{
    long len;
    struct hdr hdr;
    const char *err;
    int state = 0;
    static unsigned char buf[1<<12];  /* size must be divisible by 8 */

    if (fseek(stdin, 28*(1 + entry), 0)) {
        return "could not seek to entry header";
    }

    err = load_hdr(&hdr, entry);
    if (err) {
        return err;
    }

    if (fseek(stdin, hdr.off, 0)) {
        return "could not seek to entry data";
    }

    len = hdr.len;
    while (len) {
        long n = len > (long)sizeof(buf) ? (long)sizeof(buf) : len;
        if (!fread(buf, n, 1, stdin)) {
            return "unexpected end of input";
        }
        if (hdr.flags) {
            state = decrypt(buf, n, state);
        }
        fwrite(buf, n, 1, stdout);
        len -= n;
    }

    return 0;
}

static int
usage(FILE *f)
{
    static const char usage[] =
    "usage: glb <FILE0000.GLB [-ht] [-x #]\n"
    "  -h     print this message\n"
    "  -t     list archive contexts [default]\n"
    "  -x #   extract entry # from the archive\n";
    return fwrite(usage, sizeof(usage)-1, 1, f) && !fflush(f);
}

static const char *
run(int argc, char **argv)
{
    char *end;
    int option;
    const char *err;
    unsigned char buf[28];
    long nfiles, extract = -1;
    struct xgetopt xgo = {0, 0, 0, 0};
    static const unsigned char empty[20];

    #if __MSDOS__
    int setmode(int, int);
    setmode(0, 0x8000);
    setmode(1, 0x8000);
    #elif _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    while ((option = xgetopt(&xgo, argc, argv, "htx:")) != -1) {
        switch (option) {
        case 'h': return usage(stdout) ? 0 : "output error";
        case 't': break;
        case 'x': errno = 0;
                  extract = strtol(xgo.optarg, &end, 10);
                  if (extract < 0 || *end || errno) {
                      return "-x: invalid entry number";
                  }
                  break;
        case '?': usage(stderr);
                  sprintf(errbuf, "unknown option: -%c", xgo.optopt);
                  return errbuf;
        case ':': usage(stderr);
                  sprintf(errbuf, "-%c: missing option argument", xgo.optopt);
                  return errbuf;
        }
    }

    if (xgo.optind != argc) {
        return "too many arguments";
    }

    /* Read file header and extract the file count */
    if (!fread(buf, 28, 1, stdin)) {
        return "unexpected end of input";
    }
    decrypt(buf, 28, 0);
    if (load_u32le(buf) || memcmp(buf+8, empty, 20)) {
        return "input not in GLB format";
    }
    nfiles = load_u32le(buf+4);
    if (nfiles < 0 || nfiles > 1L<<20) {
        return "input not in GLB format";
    }

    if (extract >= 0) {
        err = cmd_extract(extract);
    } else {
        err = cmd_list(nfiles);
    }
    if (err) {
        return err;
    }

    fflush(stdout);
    return ferror(stdout) ? "write error" : 0;
}

int
main(int argc, char **argv)
{
    const char *err = run(argc, argv);
    if (err) {
        fprintf(stderr, "glb: %s\n", err);
        return 1;
    }
    return 0;
}
