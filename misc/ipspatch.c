/* IPS patch tool
 *   $ cc -Os -o ipspatch.c ipspatch.c
 *   $ ./ipspatch <PATCH TARGET
 * Ref: https://zerosoft.zophar.net/ips.php
 * This is free and unencumbered software released into the public domain.
 */
#include <stdio.h>
#include <string.h>

static char *patch(char *path)
{
    FILE *target;
    unsigned char buf[1<<12];

    target = fopen(path, "r+b");
    if (!target) {
        return "could not open patch target";
    }

    if (!fread(buf, 5, 1, stdin) || memcmp(buf, "PATCH", 5)) {
        return "invalid patch file (bad header)";
    }

    for (;;) {
        long off, len;
        int rlen = fread(buf, 1, 5, stdin);
        switch (rlen) {
        case 4:
        case 3: if (!memcmp(buf, "EOF", 3)) {
                    fflush(target);
                    return ferror(target) ? "write to target failed" : 0;
                } /* fallthrough */
        case 2:
        case 1:
        case 0: return "unexpected patch EOF";
        }

        off = (long)buf[0]<<16 | (long)buf[1]<<8 | (long)buf[2];
        if (fseek(target, off, SEEK_SET)) {
            return "target seek failed";
        }
        len = (long)buf[3]<<8  | (long)buf[4];

        if (len) {
            while (len) {
                int amt = (int)sizeof(buf)<len ? (int)sizeof(buf) : len;
                if (!fread(buf, amt, 1, stdin)) {
                    return "unexpected patch EOF";
                }
                fwrite(buf, amt, 1, target);
                len -= amt;
            }
        } else {
            if (!fread(buf, 3, 1, stdin)) {
                return "unexpected patch EOF";
            }
            len = (long)buf[0]<<8 | (long)buf[1];
            memset(buf, buf[2], sizeof(buf));
            while (len) {
                int amt = (int)sizeof(buf)<len ? (int)sizeof(buf) : len;
                fwrite(buf, amt, 1, target);
                len -= amt;
            }
        }
    }
}

int main(int argc, char **argv)
{
    char *err;

    #if _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    #endif

    if (argc != 2) {
        fputs("usage: ipspatch <PATCH TARGET\n", stderr);
        return 1;
    }

    err = patch(argv[1]);
    if (err) {
        fprintf(stderr, "ipspatch: %s\n", err);
        return 1;
    }
    return 0;
}
