#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "monocypher.h"
#include "platform.h"

#define PROG           "monocrypt"
#define MAXPASS        128
/* CHUNKLEN, NB_BLOCKS, and NB_ITERATIONS affect file format */
#define CHUNKLEN       ((1L << 26) - 16)
#define NB_BLOCKS      (1L << 18)
#define NB_ITERATIONS  3

/* prealloated buffers */
static union {
    uint8_t chunk[CHUNKLEN+16];
    uint64_t work_area[NB_BLOCKS*1024/sizeof(uint64_t)];
} buf;

enum error {ERR_OK, ERR_ENT, ERR_READ, ERR_WRITE, ERR_TRUNC, ERR_INVALID};
static const char *errmsg[] = {
    [ERR_ENT] = "failed to gather entropy",
    [ERR_READ] = "input error",
    [ERR_WRITE] = "output error",
    [ERR_TRUNC] = "input is truncated",
    [ERR_INVALID] = "wrong password / bad input",
};

static void
increment(uint8_t nonce[24])
{
    for (int i = 0; i < 24; i++) {
        if (++nonce[i]) {
            break;
        }
    }
}

static enum error
fencrypt(FILE *in, FILE *out, uint8_t *password, int pwlen)
{
    uint8_t key[32];
    uint8_t nonce[24];
    enum error err = ERR_OK;

    if (fillrand(nonce, sizeof(nonce))) {
        return ERR_ENT;
    }

    /* first 24 bytes of the file is the nonce */
    if (!fwrite(nonce, sizeof(nonce), 1, out)) {
        return ERR_WRITE;
    }

    crypto_argon2i(
        key, sizeof(key),
        buf.work_area, NB_BLOCKS, NB_ITERATIONS,
        password, pwlen,
        nonce, sizeof(nonce)
    );
    crypto_wipe(password, MAXPASS);

    for (;; increment(nonce)) {
        size_t n = fread(buf.chunk, 1, CHUNKLEN, in);
        if (!n && ferror(in)) {
            err = ERR_READ;
            break;
        }
        /* note: zero-length chunk is fine */

        uint8_t *mac = buf.chunk + n;
        crypto_lock(mac, buf.chunk, key, nonce, buf.chunk, n);
        if (!fwrite(buf.chunk, n+16, 1, out)) {
            err = ERR_WRITE;
            break;
        }

        /* short chunk indicates end of input */
        if (n < CHUNKLEN) {
            err = fflush(out) ? ERR_WRITE : ERR_OK;
            break;
        }
    }

    crypto_wipe(key, sizeof(key));
    return err;
}

static enum error
fdecrypt(FILE *in, FILE *out, uint8_t *password, int pwlen)
{
    uint8_t key[32];
    uint8_t nonce[24];
    enum error err = ERR_OK;

    /* first 24 bytes of the file is the IV */
    if (!fread(nonce, sizeof(nonce), 1, in)) {
        return ferror(in) ? ERR_READ : ERR_TRUNC;
    }

    crypto_argon2i(
        key, sizeof(key),
        buf.work_area, NB_BLOCKS, NB_ITERATIONS,
        password, pwlen,
        nonce, sizeof(nonce)
    );
    crypto_wipe(password, MAXPASS);

    for (;; increment(nonce)) {
        size_t n = fread(buf.chunk, 1, sizeof(buf.chunk), in);
        if (!n && ferror(in)) {
            err = ERR_READ;
            break;
        }
        if (n < 16) {
            err = ERR_TRUNC;
            break;
        }
        n -= 16; /* chop off MAC */

        uint8_t *mac = buf.chunk + n;
        if (crypto_unlock(buf.chunk, key, nonce, mac, buf.chunk, n)) {
            err = ERR_INVALID;
            break;
        }
        if (n && !fwrite(buf.chunk, n, 1, out)) {
            err = ERR_WRITE;
            break;
        }

        /* short chunk indicates end of input */
        if (n < CHUNKLEN) {
            err = fflush(out) ? ERR_WRITE : ERR_OK;
            break;
        }
    }

    crypto_wipe(key, sizeof(key));
    return err;
}

static int xoptind = 1;
static int xopterr = 1;
static int xoptopt;
static char *xoptarg;

static int
xgetopt(int argc, char * const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;
    (void)argc;

    /* reset? */
    if (xoptind == 0) {
        xoptind = 1;
        optpos = 1;
    }

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
                    fprintf(stderr, "%s: option requires an argument: %c\n",
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
    fputs("usage: " PROG " <-E|-D> [-h] [-o FILE] [-p PASSWORD] [FILE]\n", f);
}

int
main(int argc, char *argv[])
{
    enum {MODE_NONE, MODE_ENCRYPT, MODE_DECRYPT} mode = MODE_NONE;
    const char *outfile = 0;
    const char *infile = 0;
    uint8_t password[MAXPASS];
    int pwlen = 0;
    enum error err;

    int option;
    while ((option = xgetopt(argc, argv, "DEho:p:")) != -1) {
        switch (option) {
        case 'D': mode = MODE_DECRYPT; break;
        case 'E': mode = MODE_ENCRYPT; break;
        case 'h': usage(stdout); return 0;
        case 'o': outfile = xoptarg; break;
        case 'p': {
            size_t len = strlen(xoptarg) + 1;
            if (len > MAXPASS) {
                fprintf(
                    stderr, PROG ": password must be < %d bytes\n", MAXPASS
                );
                return 1;
            }
            pwlen = len;
            memcpy(password, xoptarg, len);
        } break;
        default: usage(stderr); return 1;
        }
    }

    binary_stdio();

    if (mode == MODE_NONE) {
        usage(stderr);
        return 1;
    }

    if (!pwlen) {
        int r0 = read_password(password, sizeof(password), "password: ");
        if (r0 == 0) {
            fputs(PROG ": failed to read password\n", stderr);
            return 1;
        }
        if (r0 < 0) {
            fprintf(stderr, PROG ": password must be < %d bytes\n", MAXPASS);
            return 1;
        }
        if (mode == MODE_ENCRYPT) {
            uint8_t tmp[MAXPASS];
            int r1 = read_password(tmp, sizeof(tmp), "password (repeat): ");
            if (r1 == 0) {
                fputs(PROG ": failed to read password\n", stderr);
                return 1;
            }
            if (r0 != r1 || memcmp(password, tmp, r0)) {
                fputs(PROG ": passwords don't match\n", stderr);
                return 1;
            }
            crypto_wipe(tmp, sizeof(tmp));
        }
        pwlen = r0;
    }

    if (argv[xoptind] && argv[xoptind+1]) {
        usage(stderr);
        return 1;
    }
    infile = argv[xoptind];

    FILE *in = !infile || !strcmp(infile, "-") ? stdin : fopen(infile, "rb");
    if (!in) {
        fprintf(stderr, PROG ": could not open input file: %s\n", infile);
        return 1;
    }
    FILE *out = !outfile ? stdout : fopen(outfile, "wb");
    if (!out) {
        fprintf(stderr, PROG ": could not open output file: %s\n", outfile);
        return 1;
    }

    switch (mode) {
    case MODE_ENCRYPT: err = fencrypt(in, out, password, pwlen); break;
    case MODE_DECRYPT: err = fdecrypt(in, out, password, pwlen); break;
    default: return 1;
    }
    if (outfile) {
        if (fclose(out) && err == ERR_OK) {
            err = ERR_WRITE;
        }
    }
    if (infile) {
        fclose(in);
    }

    if (err) {
        fprintf(stderr, PROG ": %s\n", errmsg[err]);
        if (outfile) {
            remove(outfile);
        }
        return 1;
    }
    return 0;
}
