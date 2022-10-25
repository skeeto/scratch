/* MD2 hash function implemented in ANSI C
 *
 * When compiled with GCC, performance benefits significantly from
 * -funroll-loops. Clang more aggressively unrolls loops, so this is
 *  essentially the default.
 *
 * Ref: https://tools.ietf.org/html/rfc1319
 *
 * This is free and unencumbered software released into the public domain.
 */
#include <stddef.h>

#define MD2_BLOCK_SIZE 16

struct md2 {
    int L, f;
    unsigned char c[MD2_BLOCK_SIZE];
    unsigned char x[MD2_BLOCK_SIZE * 3];
};

static void md2_init(struct md2 *);
static void md2_append(struct md2 *, const void *, size_t);
static void md2_finish(struct md2 *, void *);

/* Implementation */

static void
md2_init(struct md2 *ctx)
{
    int i;
    ctx->L = 0;
    ctx->f = 0;
    for (i = 0; i < (int)sizeof(ctx->c); i++)
        ctx->c[i] = 0;
    for (i = 0; i < (int)sizeof(ctx->x); i++)
        ctx->x[i] = 0;
}

static void
md2_append(struct md2 *ctx, const void *buf, size_t len)
{
    static const unsigned char s[] = {
        0x29, 0x2e, 0x43, 0xc9, 0xa2, 0xd8, 0x7c, 0x01, 0x3d, 0x36, 0x54,
        0xa1, 0xec, 0xf0, 0x06, 0x13, 0x62, 0xa7, 0x05, 0xf3, 0xc0, 0xc7,
        0x73, 0x8c, 0x98, 0x93, 0x2b, 0xd9, 0xbc, 0x4c, 0x82, 0xca, 0x1e,
        0x9b, 0x57, 0x3c, 0xfd, 0xd4, 0xe0, 0x16, 0x67, 0x42, 0x6f, 0x18,
        0x8a, 0x17, 0xe5, 0x12, 0xbe, 0x4e, 0xc4, 0xd6, 0xda, 0x9e, 0xde,
        0x49, 0xa0, 0xfb, 0xf5, 0x8e, 0xbb, 0x2f, 0xee, 0x7a, 0xa9, 0x68,
        0x79, 0x91, 0x15, 0xb2, 0x07, 0x3f, 0x94, 0xc2, 0x10, 0x89, 0x0b,
        0x22, 0x5f, 0x21, 0x80, 0x7f, 0x5d, 0x9a, 0x5a, 0x90, 0x32, 0x27,
        0x35, 0x3e, 0xcc, 0xe7, 0xbf, 0xf7, 0x97, 0x03, 0xff, 0x19, 0x30,
        0xb3, 0x48, 0xa5, 0xb5, 0xd1, 0xd7, 0x5e, 0x92, 0x2a, 0xac, 0x56,
        0xaa, 0xc6, 0x4f, 0xb8, 0x38, 0xd2, 0x96, 0xa4, 0x7d, 0xb6, 0x76,
        0xfc, 0x6b, 0xe2, 0x9c, 0x74, 0x04, 0xf1, 0x45, 0x9d, 0x70, 0x59,
        0x64, 0x71, 0x87, 0x20, 0x86, 0x5b, 0xcf, 0x65, 0xe6, 0x2d, 0xa8,
        0x02, 0x1b, 0x60, 0x25, 0xad, 0xae, 0xb0, 0xb9, 0xf6, 0x1c, 0x46,
        0x61, 0x69, 0x34, 0x40, 0x7e, 0x0f, 0x55, 0x47, 0xa3, 0x23, 0xdd,
        0x51, 0xaf, 0x3a, 0xc3, 0x5c, 0xf9, 0xce, 0xba, 0xc5, 0xea, 0x26,
        0x2c, 0x53, 0x0d, 0x6e, 0x85, 0x28, 0x84, 0x09, 0xd3, 0xdf, 0xcd,
        0xf4, 0x41, 0x81, 0x4d, 0x52, 0x6a, 0xdc, 0x37, 0xc8, 0x6c, 0xc1,
        0xab, 0xfa, 0x24, 0xe1, 0x7b, 0x08, 0x0c, 0xbd, 0xb1, 0x4a, 0x78,
        0x88, 0x95, 0x8b, 0xe3, 0x63, 0xe8, 0x6d, 0xe9, 0xcb, 0xd5, 0xfe,
        0x3b, 0x00, 0x1d, 0x39, 0xf2, 0xef, 0xb7, 0x0e, 0x66, 0x58, 0xd0,
        0xe4, 0xa6, 0x77, 0x72, 0xf8, 0xeb, 0x75, 0x4b, 0x0a, 0x31, 0x44,
        0x50, 0xb4, 0x8f, 0xed, 0x1f, 0x1a, 0xdb, 0x99, 0x8d, 0x33, 0x9f,
        0x11, 0x83, 0x14
    };
    int j, k, t;
    const unsigned char *m;

    m = buf;
    while (len) {
        /* Absorb input block */
        for (; len && ctx->f < 16; len--, ctx->f++) {
            int b = *m++;
            ctx->x[ctx->f + 16] = b;
            ctx->x[ctx->f + 32] = b ^ ctx->x[ctx->f];
            ctx->L = ctx->c[ctx->f] ^= s[b ^ ctx->L];
        }

        /* Transform */
        if (ctx->f == MD2_BLOCK_SIZE) {
            ctx->f = 0;
            t = 0;
            for (j = 0; j < 18; j++) {
                for (k = 0; k < 48; k++)
                    t = ctx->x[k] ^= s[t];
                t = (t + j) % 256;
            }
        }
    }
}

static void
md2_finish(struct md2 *ctx, void *digest)
{
    int i, n;
    unsigned char *out;
    unsigned char pad[MD2_BLOCK_SIZE];

    /* Append padding */
    n = MD2_BLOCK_SIZE - ctx->f;
    for (i = 0; i < n; i++)
        pad[i] = n;
    md2_append(ctx, pad, n);

    /* Append checksum */
    md2_append(ctx, ctx->c, sizeof(ctx->c));

    out = digest;
    for (i = 0; i < 16; i++)
        out[i] = ctx->x[i];
}


#if TEST
#include <stdio.h>
#include <string.h>

static int
test(const char *buf, const char *hexdigest)
{
    int i;
    struct md2 ctx[1];
    unsigned char digest[MD2_BLOCK_SIZE];

    md2_init(ctx);
    md2_append(ctx, buf, strlen(buf));
    md2_finish(ctx, digest);

    for (i = 0; i < MD2_BLOCK_SIZE; i++) {
        static const char hex[16] = "0123456789abcdef";
        if (hexdigest[i * 2 + 0] != hex[digest[i] >> 4])
            return 0;
        if (hexdigest[i * 2 + 1] != hex[digest[i] & 0xf])
            return 0;
    }
    return 1;
}

int
main(void)
{
    static const char *const tests[] = {
        "", "8350e5a3e24c153df2275c9f80692773",
        "a", "32ec01ec4a6dac72c0ab96fb34c0b5d1",
        "abc", "da853b0d3f88d99b30283a69e6ded6bb",
        "message digest", "ab4f496bfb2a530b219ff33031fe06b0",
        "abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "da33def2a42df13975352846c30338cd",
        "123456789012345678901234567890123456789012345678901234567890123"
            "45678901234567890", "d5976f79d83d3a0dc9806c3c66f3efd8"
    };
    int i;
    int pass = 0;
    int n = sizeof(tests) / sizeof(tests[0]) / 2;

    for (i = 0; i < n; i++) {
        const char *buf = tests[i * 2 + 0];
        const char *digest = tests[i * 2 + 1];
        if (!test(buf, digest))
            printf("FAIL: %s\n", buf);
        else
            pass++;
    }

    printf("Passed %d / %d\n", pass, n);
    return !(pass == n);
}
#endif


#if CLI
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(void)
{
    int i;
    struct md2 md2[1];
    static char buf[1024 * 1024];
    static char hexdigest[MD2_BLOCK_SIZE * 2 + 1];
    static unsigned char digest[MD2_BLOCK_SIZE];

#ifdef _WIN32
    {
        int _setmode(int, int);
        _setmode(0, 0x8000);
        _setmode(1, 0x8000);
    }
#endif

    md2_init(md2);
    for (;;) {
        size_t len = fread(buf, 1, sizeof(buf), stdin);
        md2_append(md2, buf, len);
        if (len < sizeof(buf))
            break;
    }
    if (!feof(stdin)) {
        fputs("md2sum: input error\n", stderr);
        exit(EXIT_FAILURE);
    }

    md2_finish(md2, digest);
    for (i = 0; i < MD2_BLOCK_SIZE; i++) {
        static const char hex[16] = "0123456789abcdef";
        hexdigest[i * 2 + 0] = hex[digest[i] >> 4];
        hexdigest[i * 2 + 1] = hex[digest[i] & 0xf];
    }
    hexdigest[MD2_BLOCK_SIZE * 2] = '\n';
    fwrite(hexdigest, sizeof(hexdigest), 1, stdout);
    if (fflush(stdout) == -1) {
        fprintf(stderr, "md2sum: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return 0;
}
#endif
