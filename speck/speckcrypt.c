/* Speck128/128 encryption demo
 *
 * - Key is a 32-byte file: 16-byte CBC key, 16-byte MAC key
 * - Plaintext encrypted with CBC mode Speck128/128
 * - Ciphertext authenticated with EtM Speck128/128-CBC-MAC
 * - All integers serialized as little endian
 * - Can only encrypt and decrypt files (not pipes)
 * - Runs on any POSIX system
 *
 * Format:
 * - 16-byte IV
 * - 16-byte MAC
 * - 16-byte data length, encrypted and authenticated
 * - N-bytes of ciphertext, rounded up to nearest 16 byte block
 *
 * Final block is zero padded as needed.
 */
#define _POSIX_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>    // getopt(3)
#include <unistd.h>    // fstat(2)
#include <sys/stat.h>  // struct stat

#include "speck.h"

#define FATAL(s) \
    do { \
        fputs("speckcrypt: " s "\n", stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

static void
usage(FILE *f)
{
    fputs("speckcrypt -D|-E -k KEYFILE INFILE [OUTFILE]\n", f);
}

static uint64_t
decode_u64le(const unsigned char *b)
{
    return ((uint64_t)b[0] <<  0) |
           ((uint64_t)b[1] <<  8) |
           ((uint64_t)b[2] << 16) |
           ((uint64_t)b[3] << 24) |
           ((uint64_t)b[4] << 32) |
           ((uint64_t)b[5] << 40) |
           ((uint64_t)b[6] << 48) |
           ((uint64_t)b[7] << 56);
}

static void
encode_u64le(unsigned char *b, uint64_t v)
{
    b[0] = (unsigned char)(v >>  0);
    b[1] = (unsigned char)(v >>  8);
    b[2] = (unsigned char)(v >> 16);
    b[3] = (unsigned char)(v >> 24);
    b[4] = (unsigned char)(v >> 32);
    b[5] = (unsigned char)(v >> 40);
    b[6] = (unsigned char)(v >> 48);
    b[7] = (unsigned char)(v >> 56);
}

static void
key_load(uint64_t keys[4], char *keyfile)
{
    FILE *k = fopen(keyfile, "rb");
    if (!k) {
        perror(keyfile);
        exit(EXIT_FAILURE);
    }

    unsigned char buf[32];
    if (!fread(buf, sizeof(buf), 1, k)) {
        if (ferror(k)) {
            perror(keyfile);
            exit(EXIT_FAILURE);
        }
        FATAL("keyfile must be 32 bytes");
    }
    fclose(k);

    for (int i = 0; i < 4; i++)
        keys[i] = decode_u64le(buf + i * 8);
}

static void
iv_generate(uint64_t iv[2])
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        perror("/dev/urandom");
        exit(EXIT_FAILURE);
    }

    unsigned char buf[128];
    if (!fread(buf, sizeof(buf), 1, f)) {
        if (ferror(f)) {
            perror("/dev/urandom");
            exit(EXIT_FAILURE);
        }
        FATAL("failed to generate an IV");
    }
    fclose(f);

    for (int i = 0; i < 2; i++)
        iv[i] = decode_u64le(buf + i * 8);
}

static void
encrypt(char *infile, char *outfile, char *keyfile)
{
    /* Initialize all keys from the keyfile */
    uint64_t keys[4];
    struct speck crypt[1];
    struct speck cbcmac[1];
    key_load(keys, keyfile);
    speck_init(crypt, keys[0], keys[1]);
    speck_init(cbcmac, keys[2], keys[3]);

    /* Go get a fresh IV */
    uint64_t iv[2];
    iv_generate(iv);

    /* Determine the output filename */
    int free_outfile = 0;
    if (!outfile) {
        size_t len = strlen(infile);
        outfile = malloc(len + 7);
        if (!outfile)
            FATAL("out of memory");
        memcpy(outfile, infile, len);
        memcpy(outfile + len, ".speck", 7);
        free_outfile = 1;
    }

    /* Open the input and output files */
    FILE *fi = fopen(infile, "rb");
    if (!fi) {
        perror(infile);
        exit(EXIT_FAILURE);
    }
    FILE *fo = fopen(outfile, "wb");
    if (!fo) {
        perror(outfile);
        exit(EXIT_FAILURE);
    }

    /* Write the IV */
    unsigned char ivbuf[16];
    encode_u64le(ivbuf + 0, iv[0]);
    encode_u64le(ivbuf + 8, iv[1]);
    if (!fwrite(ivbuf, sizeof(ivbuf), 1, fo)) {
        perror(outfile);
        fclose(fo);
        remove(outfile);
        exit(EXIT_FAILURE);
    }

    /* Reserve space for the MAC */
    fpos_t macpos[1];
    fgetpos(fo, macpos);
    unsigned char macbuf[16] = {0};
    if (!fwrite(macbuf, sizeof(macbuf), 1, fo)) {
        perror(outfile);
        fclose(fo);
        remove(outfile);
        exit(EXIT_FAILURE);
    }

    /* Ask OS for the file's length */
    struct stat stat;
    if (fstat(fileno(fi), &stat)) {
        perror(infile);
        fclose(fo);
        remove(outfile);
        exit(EXIT_FAILURE);
    }
    uint64_t ilen = stat.st_size;

    /* Encrypt and authenticate the file length */
    uint64_t mac[2];
    uint64_t block[2];
    block[0] = ilen ^ iv[0];
    block[1] = iv[1];
    speck_encrypt(crypt, block + 0, block + 1);
    mac[0] = block[0];
    mac[1] = block[1];
    speck_encrypt(cbcmac, mac + 0, mac + 1);

    /* Write the encrypted and authenticated file length */
    unsigned char lenbuf[16];
    encode_u64le(lenbuf + 0, block[0]);
    encode_u64le(lenbuf + 8, block[1]);
    if (!fwrite(lenbuf, sizeof(lenbuf), 1, fo)) {
        perror(outfile);
        fclose(fo);
        remove(outfile);
        exit(EXIT_FAILURE);
    }

    /* Encrypt all input, zero padding the last block */
    uint64_t nblocks = (ilen + 15) / 16;
    for (uint64_t i = 0; i < nblocks; i++) {
        /* Read next block of input */
        unsigned char buf[16] = {0};
        int z = fread(buf, 1, sizeof(buf), fi);
        if (z == 0) {
            if (ferror(fi)) {
                perror(outfile);
                fclose(fo);
                remove(outfile);
                exit(EXIT_FAILURE);
            }
            fclose(fo);
            remove(outfile);
            FATAL("unexpected end of input");
        }

        /* Encrypt and authenticate this block */
        block[0] ^= decode_u64le(buf + 0);
        block[1] ^= decode_u64le(buf + 8);
        speck_encrypt(crypt, block + 0, block + 1);
        mac[0] ^= block[0];
        mac[1] ^= block[1];
        speck_encrypt(cbcmac, mac + 0, mac + 1);

        /* Write out the encrypted block */
        encode_u64le(buf + 0, block[0]);
        encode_u64le(buf + 8, block[1]);
        if (!fwrite(buf, sizeof(buf), 1, fo)) {
            perror(outfile);
            fclose(fo);
            remove(outfile);
            exit(EXIT_FAILURE);
        }
    }

    /* Go back and write in the MAC */
    encode_u64le(macbuf + 0, mac[0]);
    encode_u64le(macbuf + 8, mac[1]);
    if (fsetpos(fo, macpos)) {
        perror(outfile);
        fclose(fo);
        remove(outfile);
        exit(EXIT_FAILURE);
    }
    if (!fwrite(macbuf, sizeof(macbuf), 1, fo)) {
        perror(outfile);
        fclose(fo);
        remove(outfile);
        exit(EXIT_FAILURE);
    }

    /* Make sure the output file closed properly */
    if (fclose(fo)) {
        perror(outfile);
        remove(outfile);
        exit(EXIT_FAILURE);
    }

    fclose(fi);
    if (free_outfile)
        free(outfile);
}

static void
decrypt(char *infile, char *outfile, char *keyfile)
{
    /* Initialize all keys from the keyfile */
    uint64_t keys[4];
    struct speck crypt[1];
    struct speck cbcmac[1];
    key_load(keys, keyfile);
    speck_init(crypt, keys[0], keys[1]);
    speck_init(cbcmac, keys[2], keys[3]);

    /* Determine the output filename */
    int free_outfile = 0;
    if (!outfile) {
        size_t len = strlen(infile);
        if (strcmp(infile + len - 6, ".speck") != 0)
            FATAL("could not determine output filename");
        outfile = malloc(len - 6);
        if (!outfile)
            FATAL("out of memory");
        memcpy(outfile, infile, len - 6);
        outfile[len - 6] = 0;
        free_outfile = 1;
    }

    /* Open the input and output files */
    FILE *fi = fopen(infile, "rb");
    if (!fi) {
        perror(infile);
        exit(EXIT_FAILURE);
    }
    FILE *fo = fopen(outfile, "wb");
    if (!fo) {
        perror(outfile);
        exit(EXIT_FAILURE);
    }

    /* Read the IV */
    uint64_t iv[2];
    unsigned char ivbuf[16];
    if (!fread(ivbuf, sizeof(ivbuf), 1, fi)) {
        if (ferror(fi)) {
            perror(outfile);
            fclose(fo);
            remove(outfile);
            exit(EXIT_FAILURE);
        }
        fclose(fo);
        remove(outfile);
        FATAL("unexpected end of input");
    }
    iv[0] = decode_u64le(ivbuf + 0);
    iv[1] = decode_u64le(ivbuf + 8);

    /* Read the MAC */
    uint64_t inmac[2];
    unsigned char macbuf[16];
    if (!fread(macbuf, sizeof(macbuf), 1, fi)) {
        if (ferror(fi)) {
            perror(outfile);
            fclose(fo);
            remove(outfile);
            exit(EXIT_FAILURE);
        }
        fclose(fo);
        remove(outfile);
        FATAL("unexpected end of input");
    }
    inmac[0] = decode_u64le(macbuf + 0);
    inmac[1] = decode_u64le(macbuf + 8);

    /* Read the length */
    uint64_t len[2];
    unsigned char lenbuf[16];
    if (!fread(lenbuf, sizeof(lenbuf), 1, fi)) {
        if (ferror(fi)) {
            perror(outfile);
            fclose(fo);
            remove(outfile);
            exit(EXIT_FAILURE);
        }
        fclose(fo);
        remove(outfile);
        FATAL("unexpected end of input");
    }
    len[0] = decode_u64le(lenbuf + 0);
    len[1] = decode_u64le(lenbuf + 8);

    /* Decrypt the length */
    uint64_t last[2];
    uint64_t mac[2] = {len[0], len[1]};
    uint64_t tmp[2] = {len[0], len[1]};
    speck_encrypt(cbcmac, mac + 0, mac + 1);
    speck_decrypt(crypt, len + 0, len + 1);
    len[0] ^= iv[0];
    len[1] ^= iv[1];
    last[0] = tmp[0];
    last[1] = tmp[1];

    /* Decrypt the rest of the file */
    uint64_t nblocks = (*len + 15) / 16;
    for (uint64_t i = 0; i < nblocks; i++) {
        /* Read the next block */
        uint64_t block[2];
        unsigned char buf[16];
        int z = fread(buf, sizeof(buf), 1, fi);
        if (z == 0) {
            if (ferror(fi)) {
                perror(outfile);
                fclose(fo);
                remove(outfile);
                exit(EXIT_FAILURE);
            }
            fclose(fo);
            remove(outfile);
            FATAL("unexpected end of input");
        }

        /* Decrypt and authenticate */
        tmp[0] = block[0] = decode_u64le(buf + 0);
        tmp[1] = block[1] = decode_u64le(buf + 8);
        mac[0] ^= block[0];
        mac[1] ^= block[1];
        speck_encrypt(cbcmac, mac + 0, mac + 1);
        speck_decrypt(crypt, block + 0, block + 1);
        block[0] ^= last[0];
        block[1] ^= last[1];
        last[0] = tmp[0];
        last[1] = tmp[1];

        /* Last block may be partial */
        if (i == nblocks - 1 && *len % 16)
            z = *len % 16;
        else
            z = sizeof(buf);

        /* Write out block */
        encode_u64le(buf + 0, block[0]);
        encode_u64le(buf + 8, block[1]);
        if (!fwrite(buf, z, 1, fo)) {
            perror(outfile);
            fclose(fo);
            remove(outfile);
            exit(EXIT_FAILURE);
        }
    }

    /* Make sure the output file closed properly */
    if (fclose(fo)) {
        perror(outfile);
        remove(outfile);
        exit(EXIT_FAILURE);
    }

    /* Compare our MAC to the input MAC */
    if (mac[0] != inmac[0] || mac[1] != inmac[1]) {
        remove(outfile);
        FATAL("bad key or ciphertext is corrupt (MAC)");
    }

    fclose(fi);
    if (free_outfile)
        free(outfile);
}

int
main(int argc, char **argv)
{
    char *infile = 0;
    char *outfile = 0;
    char *keyfile = 0;
    enum {M_ENCRYPT = 1, M_DECRYPT} mode = 0;

    int option;
    while ((option = getopt(argc, argv, "DEhk:")) != -1) {
        switch (option) {
            case 'D':
                mode = M_DECRYPT;
                break;
            case 'E':
                mode = M_ENCRYPT;
                break;
            case 'h':
                usage(stdout);
                exit(EXIT_SUCCESS);
                break;
            case 'k':
                keyfile = optarg;
                break;
            default:
                usage(stderr);
                exit(EXIT_FAILURE);
        }
    }

    if (!keyfile) {
        fputs("speckcrypt: requires a keyfile (-k)\n", stderr);
        usage(stderr);
        exit(EXIT_FAILURE);
    }

    infile = argv[optind];
    if (!infile) {
        fputs("speckcrypt: requires an input file\n", stderr);
        usage(stderr);
        exit(EXIT_FAILURE);
    }
    outfile = argv[optind + 1];

    switch (mode) {
        case M_ENCRYPT:
            encrypt(infile, outfile, keyfile);
            break;
        case M_DECRYPT:
            decrypt(infile, outfile, keyfile);
            break;
        default:
            usage(stderr);
            FATAL("must select decrypt (-D) or encrypt (-E)");
    }
}
