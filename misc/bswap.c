// Base conversion in arbitrary precision
// Ref: https://old.reddit.com/r/C_Programming/comments/13iqbsb
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
#include <stdlib.h>

// Parse a small non-negative integer within range. Returns -1 on error.
static int parseint(char *s, int min, int max)
{
    int value = 0;
    int empty = 1;
    for (; *s; s++) {
        switch (*s) {
        default:
            return -1;
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            value = value*10 + (*s - '0')%10;
            empty = 0;
            if (value > max) {
                return -1;
            }
        }
    }
    return empty || value<min ? -1 : value;
}

static int bswap(unsigned char *dst, int dstlen, int base, char *src)
{
    static const char digits[36] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const unsigned char values[256] = {
        +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
        +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
        +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
        +1, +2, +3, +4, +5, +6, +7, +8, +9, 10, +0, +0, +0, +0, +0, +0,
        +0, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, +0, +0, +0, +0, +0,
        +0, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36
    };

    int ibase = 10;
    if (src[0] == '0') {
        switch (src[1]) {
        case 'x': ibase = 16; src += 2; break;
        case 'o': ibase =  8; src += 2; break;
        case 'b': ibase =  2; src += 2; break;
        }
    }
    if (!src[0]) {
        return 0;
    }

    // Parse the input into dst in the chosen base
    int len = 1;
    *dst = 0;
    for (; *src; src++) {
        int v = values[*src&255] - 1;
        if (v<0 || v >= ibase) {
            return 0;  // invalid digit
        }

        // Accumulate digit into the total
        int carry = v;
        for (int i = 0; i < len; i++) {
            int x = dst[-i]*ibase + carry;
            dst[-i] = (unsigned char)(x % base);
            carry = x / base;
        }
        while (carry) {
            if (len == dstlen) {
                return 0;  // out of memory
            }
            dst[-(len++)] = (unsigned char)(carry % base);
            carry /= base;
        }
    }

    // Convert to ASCII
    for (int i = 0; i < len; i++) {
        dst[-i] = digits[dst[-i]];
    }
    return len;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: bswap <output-base> <number>\n");
        return 1;
    }

    int base = parseint(argv[1], 2, 36);
    if (base == -1) {
        fprintf(stderr, "bswap: invalid base: %s\n", argv[1]);
        return 1;
    }

    int cap = 1 << 28;
    unsigned char *dst = malloc(cap);
    unsigned char *end = dst + cap - 1;
    *end-- = '\n';
    int len = bswap(end, cap-1, base, argv[2]);
    if (!len) {
        fprintf(stderr, "bswap: invalid number: %s\n", argv[2]);
        return 1;
    }
    fwrite(end-len+1, 1, len+1, stdout);

    fflush(stdout);
    if (ferror(stdout)) {
        fprintf(stderr, "bswap: write error\n");
        return 1;
    }
    return 0;
}
