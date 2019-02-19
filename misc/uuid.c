/* UUID (v4) generator in ANSI C
 *   $ cc -O3 -o uuid uuid.c
 *   $ uuid [count]
 * Output rate: 30 million UUIDs per second on modern hardware.
 * Warning: Generator rolls over after 2^66 UUIDs (or every 78,000 years).
 *
 * This is free and unencumbered software released into the public domain.
 */
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  pragma comment(lib, "advapi32.lib")
#endif
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static uint32_t chacha[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
static uint32_t output[16];

static int
chacha_init(void)
{
#if _WIN32
    BOOLEAN NTAPI SystemFunction036(PVOID, ULONG);
    return !SystemFunction036(chacha + 4, 48);
#else
    int r = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        r = fread(chacha + 4, 48, 1, f);
        fclose(f);
    }
    return !r;
#endif
}

static void
chacha_mix(void)
{
    int i;
    uint64_t counter;
    #define CHACHA_ROTATE(v,n) (((v) << (n)) | ((v) >> (32 - (n))))
    #define CHACHA_QUARTERROUND(x,a,b,c,d) \
        x[a] += x[b]; x[d] = CHACHA_ROTATE(x[d] ^ x[a],16); \
        x[c] += x[d]; x[b] = CHACHA_ROTATE(x[b] ^ x[c],12); \
        x[a] += x[b]; x[d] = CHACHA_ROTATE(x[d] ^ x[a], 8); \
        x[c] += x[d]; x[b] = CHACHA_ROTATE(x[b] ^ x[c], 7)
    for (i = 0; i < 16; i++)
        output[i] = chacha[i];
    for (i = 12; i > 0; i -= 2) {
        CHACHA_QUARTERROUND(output,  0,  4,  8, 12);
        CHACHA_QUARTERROUND(output,  1,  5,  9, 13);
        CHACHA_QUARTERROUND(output,  2,  6, 10, 14);
        CHACHA_QUARTERROUND(output,  3,  7, 11, 15);
        CHACHA_QUARTERROUND(output,  0,  5, 10, 15);
        CHACHA_QUARTERROUND(output,  1,  6, 11, 12);
        CHACHA_QUARTERROUND(output,  2,  7,  8, 13);
        CHACHA_QUARTERROUND(output,  3,  4,  9, 14);
    }
    for (i = 0; i < 16; i++)
        output[i] += chacha[i];
    counter = ((uint64_t)chacha[13] << 32 | chacha[12] << 0) + 1;
    chacha[12] = counter >>  0;
    chacha[13] = counter >> 32;
}

int
main(int argc, char *argv[])
{
    long i;
    long n = 1;
    static const char ver[4] = "89ab";
    static const char hex[16] = "0123456789abcdef";
    char out[37] = "........-....-4...-v...-............\n";

    /* Parse optional command line argument */
    switch (argc) {
        case 0:
        case 1: {
            n = 1;
        } break;
        case 2: {
            char *end;
            errno = 0;
            n = strtol(argv[1], &end, 10);
            if (*end || n < 0 || errno) {
                fprintf(stderr, "uuid: invalid count, %s\n", argv[1]);
                fprintf(stderr, "usage: uuid [count]\n");
                return 1;
            }
        } break;
        default: {
            fprintf(stderr, "uuid: too many arguments\n");
            return 1;
        }
    }

    if (chacha_init()) {
        fprintf(stderr, "uuid: failed to gather entropy\n");
        return 1;
    }

    for (i = 0; i < n; i++) {
        unsigned char *raw = (unsigned char *)(output + (i % 4) * 4);
        if (i % 4 == 0) chacha_mix();
        out[ 0] = hex[raw[ 0] >> 4];
        out[ 1] = hex[raw[ 0] & 15];
        out[ 2] = hex[raw[ 1] >> 4];
        out[ 3] = hex[raw[ 1] & 15];
        out[ 4] = hex[raw[ 2] >> 4];
        out[ 5] = hex[raw[ 2] & 15];
        out[ 6] = hex[raw[ 3] >> 4];
        out[ 7] = hex[raw[ 3] & 15];
        out[ 9] = hex[raw[ 4] >> 4];
        out[10] = hex[raw[ 4] & 15];
        out[11] = hex[raw[ 5] >> 4];
        out[12] = hex[raw[ 5] & 15];
        out[15] = hex[raw[ 6] & 15];
        out[16] = hex[raw[ 7] >> 4];
        out[17] = hex[raw[ 7] & 15];
        out[19] = ver[raw[ 8] &  3];
        out[20] = hex[raw[ 8] & 15];
        out[21] = hex[raw[ 9] >> 4];
        out[22] = hex[raw[ 9] & 15];
        out[24] = hex[raw[10] >> 4];
        out[25] = hex[raw[10] & 15];
        out[26] = hex[raw[11] >> 4];
        out[27] = hex[raw[11] & 15];
        out[28] = hex[raw[12] >> 4];
        out[29] = hex[raw[12] & 15];
        out[30] = hex[raw[13] >> 4];
        out[31] = hex[raw[13] & 15];
        out[32] = hex[raw[14] >> 4];
        out[33] = hex[raw[14] & 15];
        out[34] = hex[raw[15] >> 4];
        out[35] = hex[raw[15] & 15];
        if (!fwrite(out, 37, 1, stdout)) {
            fprintf(stderr, "uuid: output error\n");
            return 1;
        }
    }

    if (fflush(stdout)) {
        fprintf(stderr, "uuid: output error\n");
        return 1;
    }
    return 0;
}
