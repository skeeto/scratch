// Encode/decode arbitrary input to/from whitespace
// Ref: https://github.com/gregfoletta/whitespacer
// Ref: https://redd.it/oie8b1
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <string.h>

static unsigned char dbuf[1L<<14];
static unsigned char ebuf[4*sizeof(dbuf)];
static unsigned long long tr64[1L<<16];
static const signed char value[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, +0, +1, -1, -1, +2, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    +3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
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
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

static char *
encode(void)
{
    for (;;) {
        size_t n = fread(dbuf, 1, sizeof(dbuf), stdin);
        if (!n) {
            return feof(stdin) ? 0 : "input error";
        }

        for (size_t i = 0; i < sizeof(dbuf); i += 2) {
            unsigned long long b = tr64[dbuf[i] | (unsigned)dbuf[i+1]<<8];
            unsigned char *p = ebuf + i*4;
            p[0] = b >>  0; p[1] = b >>  8;
            p[2] = b >> 16; p[3] = b >> 24;
            p[4] = b >> 32; p[5] = b >> 40;
            p[6] = b >> 48; p[7] = b >> 56;
        }

        if (fwrite(ebuf, n, 4, stdout) != 4) {
            return "output error";
        }
    }
}

static char *
decode(void)
{
    // Fill overflow with valid input
    memset(ebuf, 9, sizeof(ebuf));

    for (;;) {
        size_t n = fread(ebuf, 1, sizeof(ebuf), stdin);
        if (!n) {
            return feof(stdin) ? 0 : "input error";
        }
        if (n & 3) {
            return "invalid input (truncated)";
        }

        int check = 0;
        for (size_t i = 0; i < sizeof(ebuf); i += 4) {
            unsigned v[] = {
                value[ebuf[i+0]], value[ebuf[i+1]],
                value[ebuf[i+2]], value[ebuf[i+3]],
            };
            int pack = v[3]<<6 | v[2]<<4 | v[1]<<2 | v[0]<<0;
            dbuf[i/4] = pack;
            check |= pack;
        }
        if (check < 0) {
            return "invalid input (bad byte)";
        }

        if (!fwrite(dbuf, n/4, 1, stdout)) {
            return "output error";
        }
    }
}

int
main(int argc, char *argv[])
{
    char *err = 0;

#ifdef _WIN32
    // Set stdin/stdout to binary mode
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
#endif

    // This program does its own buffering, so turn it off in libc
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    // Initialize the big table
    for (long i = 0; i < 1L<<16; i++) {
        static const unsigned long long s[] = {9, 10, 13, 32};
        tr64[i] = s[(i>>14)&3] << 56 | s[(i>>12)&3] << 48 |
                  s[(i>>10)&3] << 40 | s[(i>> 8)&3] << 32 |
                  s[(i>> 6)&3] << 24 | s[(i>> 4)&3] << 16 |
                  s[(i>> 2)&3] <<  8 | s[(i>> 0)&3] <<  0;
    }

    if (argc == 1 || !strcmp(argv[1], "-e")) {
        err = encode();
    } else if (argc == 2 && !strcmp(argv[1], "-d")) {
        err = decode();
    } else {
        err = "invalid arguments";
    }

    if (err) {
        fprintf(stderr, "%s: %s\n", argv[0], err);
        return 1;
    }
    return 0;
}
