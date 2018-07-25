/* Simple RC4 file encryption
 *
 * Encryption:
 * 1. Generate a unique 8-byte initialization vector (IV).
 * 2. Run RC4 key schedule once using the IV.
 * 3. Run RC4 key schedule 1024 times using the passphrase, including the
 *    null terminator.
 * 4. Emit 8-byte IV.
 * 5. Emit all input XORed with keystream.
 *
 * Decryption:
 * 1. Read 8-byte IV from input.
 * 2. Run RC4 key schedule once using the initialization vector.
 * 3. Run RC4 key schedule 1024 times using the passphrase, including the
 *    null terminator.
 * 4. Emit remaining input XORed with keystream.
 *
 * Note: There is no authentication tag!
 */
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rc4 {
    int i, j;
    unsigned char s[256];
};

static void
rc4_init(struct rc4 *r)
{
    int i;
    r->i = r->j = 0;
    for (i = 0; i < 256; i++)
        r->s[i] = i;
}

static void
rc4_key(struct rc4 *r, const void *key, int len)
{
    int tmp, i, j;
    unsigned char *k = (unsigned char *)key;
    for (i = 0, j = 0; i < 256; i++) {
        j = (j + r->s[i] + k[i % len]) & 0xff;
        tmp = r->s[i]; r->s[i] = r->s[j]; r->s[j] = tmp;
    }
}

static int
rc4_emit(struct rc4 *r)
{
    int tmp, i, j;
    unsigned char *s = r->s;
    i = r->i = (r->i + 1) & 0xff;
    j = r->j = (r->j + s[i]) & 0xff;
    tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    return s[(s[i] + s[j]) & 0xff];
}

static FILE *
efopen(const char *file, const char *mode)
{
    FILE *f = fopen(file, mode);
    if (!f) {
        fprintf(stderr, "rc4: '%s': %s\n", file, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return f;
}

/* Platform specific entropy source. */
static void geniv(void *iv);

#if __BORLANDC__
static unsigned long
hash(unsigned long x)
{
    x ^= x >> 7;
    x *= 0x2bc8f3e5UL;
    x  = (x << 15) | (x >> 17);
    x -= x << 26;
    x *= 0x101cbf8bUL;
    x  = (x << 12) | (x >> 20);
    return x;
}

static void
geniv(void *iv)
{
    /* Read from the 18.2Hz BIOS clock (46Ch) repeatedly, mixing it up
     * with an integer hash function along the way. The timing
     * variations between samples should break apart runs begun from the
     * same starting clock. This function takes ~1 second regardless of
     * the host's CPU speed, though faster CPUs will produce better
     * entropy.
     */
    int i;
    unsigned long now = time(0);
    unsigned long h0 = hash(now);
    unsigned long h1 = hash(~now);
    volatile unsigned long far *clock = (unsigned long far *)0x46cUL;
    for (i = 0; i < 18; i++) {
        unsigned long count = 0;
        unsigned long beg = *clock;
        unsigned long end;
        h0 = hash(h0 ^ beg);
        h1 = hash(h1 ^ beg);
        for (; (end = *clock) == beg; count++) {
            h0 = hash(h0 + count);
            h1 = hash(h1 + count);
        }
        h0 = hash(h0 ^ end);
        h1 = hash(h1 ^ end);
    }
    memcpy(iv, &h0, 4);
    memcpy((char *)iv + 4, &h1, 4);
}
#endif /* __BORLANDC__ */

#if __unix__
/* /dev/urandom */
static void
geniv(void *iv)
{
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        fprintf(stderr, "rc4: '/dev/urandom': %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (!fread(iv, 8, 1, urandom)) {
        fprintf(stderr, "rc4: could not gather entropy\n");
        exit(EXIT_FAILURE);
    }
    fclose(urandom);
}
#endif /* __unix__ */

#ifdef _WIN32
/* RtlGenRandom() */
#pragma comment(lib, "advapi32.lib")
unsigned char SystemFunction036(void *, unsigned long);
static void
geniv(void *iv)
{
    if (!SystemFunction036(iv, 8)) {
        fprintf(stderr, "rc4: could not gather entropy\n");
        exit(EXIT_FAILURE);
    }
}
#endif /* _WIN32 */

static void
usage(FILE *f, int status)
{
    fprintf(f, "usage: rc4 <-E|-D|-h> <KEY> [INFILE [OUTFILE]]\n");
    exit(status);
}

int
main(int argc, char **argv)
{
    int i, c;
    size_t keylen;
    const char *key;
    struct rc4 rc4[1];
    unsigned char iv[8];
    const char *mode;
    FILE *in = stdin;
    FILE *out = stdout;

    /* Parse command line arguments */
    switch (argc) {
        default: usage(stderr, EXIT_FAILURE);
        case 5: out = efopen(argv[4], "wb");
        case 4: in  = efopen(argv[3], "rb");
        case 3: key = argv[2];
                mode = argv[1];
    }
    if (mode[0] != '-')
        usage(stderr, EXIT_FAILURE);

    keylen = strlen(key) + 1;
    if (keylen > 256) {
        fprintf(stderr, "rc4: key too long\n");
        exit(EXIT_FAILURE);
    }

    rc4_init(rc4);
    switch (mode[1]) {

        /* Encrypt */
        case 'E': {
            geniv(iv);
            if (!fwrite(iv, sizeof(iv), 1, out)) {
                fprintf(stderr, "rc4: output error\n");
                exit(EXIT_FAILURE);
            }
        } break;

        /* Decrypt */
        case 'D': {
            if (!fread(iv, sizeof(iv), 1, in)) {
                fprintf(stderr, "rc4: input error\n");
                exit(EXIT_FAILURE);
            }
        } break;

        /* Help */
        case 'h':
            usage(stdout, EXIT_SUCCESS);

        default:
            usage(stderr, EXIT_FAILURE);
    }

    rc4_key(rc4, iv, sizeof(iv));
    for (i = 0; i < 1024; i++)
        rc4_key(rc4, key, keylen);
    while ((c = fgetc(in)) != EOF) {
        int k = rc4_emit(rc4);
        fputc(c ^ k, out);
    }

    if (fclose(out)) {
        fprintf(stderr, "rc4: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    fclose(in);
    return 0;
}
