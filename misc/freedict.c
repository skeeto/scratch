// FreeDict decoder example
//
//   $ cc -O -o freedict freedict.c
//   $ gunzip <example.dict.dz | ./freedict example.index
//
// This is free and unencumbered software released into the public domain.
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Decode up to five base64 bytes to a 30-bit result. Returns a negative
// result for invalid input.
static int32_t
decode64(uint8_t *s, int len)
{
    static int8_t t[] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1,+0,+1,+2,+3,+4,+5,+6,+7,+8,+9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    uint32_t v = 0;
    assert(len >= 0 && len < 6);
    for (int i = 0; i < len; i++) {
        v = v<<6 | t[s[i]];
    }
    return v;
}

struct def {
    int32_t defoff, deflen;  // index into definition buffer
    int32_t keyoff, keylen;  // index into index buffer
};

// Return the next definition offset/length from the index. Initialize
// *line to zero. Returns a negative offset on error. EOF occurs when
// *line == idxlen, which will always occur for valid input.
static struct def
next(int32_t *line, uint8_t *idxbuf, int32_t idxlen, int32_t deflen)
{
    struct def def = {-1, -1, *line, 0};

    assert(idxlen >= 0);
    assert(deflen >= 0);
    assert(*line >= 0 && *line < idxlen);

    uint8_t *p = memchr(idxbuf+*line, '\t', idxlen-*line);
    if (!p) {
        return def;
    }
    int32_t offoff = p + 1 - idxbuf;
    def.keylen = offoff - 1 - def.keyoff;

    p = memchr(idxbuf+offoff, '\t', idxlen-offoff);
    if (!p) {
        return def;
    }
    int32_t lenoff = p + 1 - idxbuf;
    int32_t offlen = lenoff - offoff - 1;

    p = memchr(idxbuf+lenoff, '\n', idxlen-lenoff);
    if (!p) {
        return def;
    }
    int32_t lenlen = p - idxbuf - lenoff;

    // Enforce a smaller range for length so that we can safely add
    // offset and length as int32_t.
    if (offlen < 1 || offlen > 5 || lenlen < 1 || lenlen > 4) {
        return def;
    }

    int32_t off = decode64(idxbuf+offoff, offlen);
    int32_t len = decode64(idxbuf+lenoff, lenlen);
    if (off < 0 || len < 0 || off+len > deflen) {
        return def;
    }

    *line = p + 1 - idxbuf;
    def.defoff = off;
    def.deflen = len;
    return def;
}

int
main(int argc, char **argv)
{
    // 64MiB ought to be enough for everything
    int32_t deflen, idxlen;
    static uint8_t defbuf[1L<<25], idxbuf[1L<<25];

    FILE *f = fopen(argv[argc-1], "rb");
    if (!f) {
        return 1;
    }
    idxlen = fread(idxbuf, 1, sizeof(idxbuf), f);
    if (ferror(f)) {
        return 1;
    }
    fclose(f);

    deflen = fread(defbuf, 1, sizeof(defbuf), stdin);
    if (ferror(stdin)) {
        return 1;
    }

    for (int32_t line = 0; line < idxlen;) {
        struct def def = next(&line, idxbuf, idxlen, deflen);
        if (def.defoff < 0) {
            return 1;
        }

        // Do something with the definition here
        puts("---");
        fwrite(defbuf+def.defoff, def.deflen, 1, stdout);
    }

    fflush(stdout);
    return ferror(stdout);
}
