/* cols: wrap standard input into columns
 *
 * Similar to the "columns" command from GNU AutoGen, and the "column"
 * command from util-linux. However, this version is more portable,
 * simpler, faster, less memory-intensive, more precise, more correct,
 * and better-licensed.
 *
 * Very roughly supports UTF-8 by assuming each code point has a display
 * width of one. This works out well in many common cases, but it will
 * not work with most CJK (i.e. double wide), glyphs composed of
 * multiple code points (combining characters, etc.), or bidirectional
 * text. (Most terminal emulators that would be displaying this
 * program's output do not handle these all correctly anyways.)
 *
 * This is free and unencumbered software released into the public domain.
 */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONF_DEFAULT {0, 80, 0, 0, 0}
struct conf {
    size_t cwidth;
    size_t twidth;
    size_t ncols;
    size_t nlines;
    size_t widest;
};

/* Byte table where whitespace is zero. Sign-extension of signed char
 * creates a full-width mask.
 */
static const signed char whitespace[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, +0, +0, +0, +0, +0, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    +0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

/* Translates all whitespace into space (0x20).
 */
static const unsigned char whitespace_tx[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x20, 0x0a, 0x20, 0x20, 0x20, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/* UTF-8 length from 4-bit prefix. Invalid UTF-8 prefixes are treated as
 * a raw byte.
 */
static const int utf8_len[16] = {1,1,1,1,1,1,1,1,1,1,1,1,2,2,3,4};

/* Read the entire standard input into a buffer. Return NULL on error.
 */
static char *
slurp(size_t *len)
{
    size_t cap, z;
    char *buf = 0;

    for (*len = 0, cap = 1<<11; cap; cap *= 2) {
        void *p = realloc(buf, cap);
        if (!p) {
            *len = 0;
            free(buf);
            return 0;
        }
        buf = p;

        z = fread(buf+*len, 1, cap-*len, stdin);
        *len += z;
        if (z < cap-*len) {
            if (feof(stdin)) {
                /* Guaranteed newline simplifies processing */
                buf[(*len)++] = 0x0a;
                return buf;
            }
            *len = 0;
            free(buf);
            return 0;
        }
    }

    *len = 0;
    free(buf);
    return 0;
}

/* Examine the buffer, counting the lines and finding the widest display
 * line width. Also "flattens" whitespace.
 */
static void
examine(char *buf, size_t buflen, struct conf *conf)
{
    size_t i;
    size_t max = 0;
    size_t len = 0;
    size_t tmp = 0;
    size_t nlines = 0;

    for (i = 0; i < buflen;) {
        /* Should work out to be branchless.
         *
         * As it scans across a line, the whitespace count accumulates
         * in tmp, which is rolled into len when a non-whitespace byte
         * is found. So if whitespace is not followed by non-whitespace,
         * the count is discarded.
         *
         * When a newline is detected, a mask clears all counters, and
         * the masks's inverse causes the line counter to update.
         */
        int b = buf[i] & 0xff;
        size_t mask = whitespace[b];
        size_t keep = -(b != 0x0a);
        nlines += (!!len) & ~keep;
        max = max > len ? max : len;
        len += ++tmp & mask;
        len &= keep;
        tmp &= keep & ~mask;
        buf[i] = whitespace_tx[b];
        i += utf8_len[b>>4];
    }
    conf->nlines = nlines;
    conf->widest = max;
}

/* Buffered output system
 *
 * Since stdio calls are slow (locking, PLT/DLL overhead), especially on
 * Windows with MSVC (poor implementation), buffer all fwrite() calls.
 */
static size_t io_len = 0;
static char io_buf[1<<14];

/* Flush output buffer, returning 0 on error.
 */
static int
io_flush(void)
{
    if (io_len && !fwrite(io_buf, io_len, 1, stdout)) {
        return 0;
    }
    io_len = 0;
    return !fflush(stdout);
}

/* Buffered write to standard output, returning 0 on error.
 */
static int
io_write(const char *buf, size_t size)
{
    /* NOTE: In some toolchains, such as musl, the memcpy() calls here
     * are the primary bottlenecks for the entire program, worse than
     * stdio (which has otherwise already been mitigated).
     */

    if (sizeof(io_buf)-1-io_len > size) {
        memcpy(io_buf+io_len, buf, size);
        io_len += size;
        return 1;
    }

    if (!io_flush()) {
        return 0;
    }

    if (size >= sizeof(io_buf)-1) {
        return fwrite(buf, size, 1, stdout);
    }

    memcpy(io_buf, buf, size);
    io_len = size;
    return 1;
}

/* Append one newline to the end of the output buffer.
 *
 * Always succeeds, but cannot be called twice in a row, without
 * io_write() or io_flush() in between. This is needed frequently, and
 * making it a special case allows for greater efficiency.
 */
static void
io_newline(void)
{
    io_buf[io_len++] = 0x0a;
}

/* Write the given number of spaces to standard output.
 */
static int
space(size_t n)
{
    static const char spaces[128] =
        "                                                                "
        "                                                                ";
    while (n) {
        size_t z = n > sizeof(spaces) ? sizeof(spaces) : n;
        if (!io_write(spaces, z)) {
            return 0;
        }
        n -= z;
    }
    return 1;
}

/* Print row-order from buffer according to configuration.
 */
static int
print_by_row(char *buf, size_t buflen, struct conf conf)
{
    size_t i;
    size_t beg = 0;
    size_t col = 0;
    size_t blen = 0;  /* byte length   */
    size_t dlen = 0;  /* display width */
    size_t btmp = 0;
    size_t dtmp = 0;

    for (i = 0; i < buflen;) {
        /* Works just like examine(), but tracks both byte length and
         * display width simultaneously. The byte width is to track
         * buffer offsets/lengths, and the display width is used to
         * layout the columns.
         */
        int b = buf[i] & 0xff;
        size_t clen = utf8_len[b>>4];
        size_t mask = whitespace[b];
        size_t keep = -(b != 0x0a);

        if (dlen & ~keep) {
            if (!io_write(buf+beg, blen)) {
                return 0;
            }

            if (++col == conf.ncols) {
                io_newline();
                col = 0;
            } else {
                if (!space(conf.cwidth - dlen + 1)) {
                    return 0;
                }
            }
        }

        btmp += clen;         dtmp += 1;
        blen += btmp & mask;  dlen += dtmp & mask;
        blen &= keep;         dlen &= keep;
        btmp &= keep & ~mask; dtmp &= keep & ~mask;
        beg = (beg&keep) | ((i+1)&~keep);
        i += clen;
    }

    if (col) {
        io_newline();
    }
    return io_flush();
}

/* Print column-order from buffer according to configuration.
 */
static int
print_by_col(char *buf, size_t buflen, struct conf conf)
{
    size_t i, r;
    size_t nrows;
    size_t *cursors;

    cursors = calloc(conf.ncols, sizeof(*cursors));
    if (!cursors) {
        return 0;
    }

    /* Advance each cursor to the top of each column. */
    nrows = (conf.nlines + conf.ncols - 1) / conf.ncols;
    for (i = 1; i < conf.ncols; i++) {
        /* Don't care about lengths, just counting non-empty lines. */
        size_t nonempty = 0;
        cursors[i] = cursors[i-1];
        for (r = 0; r < nrows; r++) {
            while (cursors[i] < buflen) {
                int b = buf[cursors[i]] & 0xff;
                size_t clen = utf8_len[b>>4];
                size_t keep = -(b != 0x0a);
                if (nonempty & ~keep) {
                    cursors[i]++;
                    break;
                }
                nonempty |= whitespace[b];
                cursors[i] += clen;
            }
        }
    }

    for (r = 0; r < nrows; r++) {
        /* Like print_by_row but advance each cursor one-by-one. */
        for (i = 0; i < conf.ncols; i++) {
            size_t blen = 0;
            size_t dlen = 0;
            size_t btmp = 0;
            size_t dtmp = 0;
            size_t beg = cursors[i];

            while (cursors[i] < buflen) {
                int b = buf[cursors[i]] & 0xff;
                size_t clen = utf8_len[b>>4];
                size_t mask = whitespace[b];
                size_t keep = -(b != 0x0a);

                if (dlen & ~keep) {
                    if (!io_write(buf+beg, blen)) {
                        free(cursors);
                        return 0;
                    }
                    if (i != conf.ncols-1) {
                        if (!space(conf.cwidth - dlen + 1)) {
                            free(cursors);
                            return 0;
                        }
                    }
                    cursors[i]++;
                    break;
                }

                btmp += clen;         dtmp += 1;
                blen += btmp & mask;  dlen += dtmp & mask;
                blen &= keep;         dlen &= keep;
                btmp &= keep & ~mask; dtmp &= keep & ~mask;
                beg = (beg&keep) | ((i+1)&~keep);
                cursors[i] += clen;
            }
        }
        io_newline();
    }

    free(cursors);
    return io_flush();
}

static int xoptind = 1;
static int xoptopt;
static char *xoptarg;

/* Like getopt(3) but never prints error messages.
 */
static int
xgetopt(int argc, char * const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;
    (void)argc;

    arg = argv[xoptind];
    if (arg && arg[0] == '-' && arg[1] == '-' && !arg[2]) {
        xoptind++;
        return -1;
    } else if (!arg || arg[0] != '-' || !isalnum(arg[1])) {
        return -1;
    } else {
        const char *opt = strchr(optstring, arg[optpos]);
        xoptopt = arg[optpos];
        if (!opt) {
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
                return ':';
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

static int
usage(FILE *f)
{
    static const char usage[] =
    "usage: cols [-Ch] [-W INT] [-w INT]\n"
    "  -C      print lines in column-order\n"
    "  -h      display usage information\n"
    "  -W INT  desired line width [80]\n"
    "  -w INT  desired column width [auto]\n";
    return fwrite(usage, sizeof(usage)-1, 1, f) && !fflush(f);
}

/* Like main(), but returns a static error string.
 */
const char *
run(int argc, char **argv)
{
    struct conf conf = CONF_DEFAULT;
    int option, r;
    long value;
    char *end, *buf;
    size_t len;
    enum {MODE_RORDER, MODE_CORDER} mode = MODE_RORDER;
    static char missing[] = "missing argument: -?";
    static char illegal[] = "illegal option: -?";

    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    while ((option = xgetopt(argc, argv, ":CW:hw:")) != -1) {
        switch (option) {
        case 'C': mode = MODE_CORDER;
                  break;
        case 'W': errno = 0;
                  value = strtol(xoptarg, &end, 10);
                  if (errno || *end || value <= 0) {
                      return "-W: invalid argument";
                  }
                  conf.twidth = value;
                  break;
        case 'h': return usage(stdout) ? 0 : "write error";
        case 'w': errno = 0;
                  value = strtol(xoptarg, &end, 10);
                  if (errno || *end || value < 1) {
                      return "-W: invalid argument";
                  }
                  conf.cwidth = value - 1;
                  break;
        case ':': missing[sizeof(missing)-2] = xoptopt;
                  usage(stderr);
                  return missing;
        case '?': illegal[sizeof(illegal)-2] = xoptopt;
                  usage(stderr);
                  return illegal;
        }
    }

    buf = slurp(&len);
    if (!buf) {
        return ferror(stdin) ? "read error" : "out of memory";
    }

    examine(buf, len, &conf);
    conf.cwidth = conf.widest > conf.cwidth ? conf.widest : conf.cwidth;
    conf.ncols = (conf.twidth + 1) / (conf.cwidth + 1);
    conf.ncols = conf.ncols ? conf.ncols : 1;

    switch (mode) {
    case MODE_RORDER: r = print_by_row(buf, len, conf); break;
    case MODE_CORDER: r = print_by_col(buf, len, conf); break;
    }
    free(buf);
    return r ? 0 : "write error";
}

int
main(int argc, char **argv)
{
    const char *err = run(argc, argv);
    if (err) {
        fprintf(stderr, "cols: %s\n", err);
        return 1;
    }
    return 0;
}