// Count unique, fixed-length substrings in a string
//
// The first input line is the test count, which is then followed by
// that many tests. The first line of each test is the string length and
// substring length, between 1 and 10^5. The second line is the string.
// Output for each test is the number of unique substrings.
//
// Use -DGENERATE to generate a large test input.
//
// Ref: https://www.spoj.com/problems/ADACLEAN/
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define assert(c)     while (!(c)) *(volatile int *)4 = 0
#define new(a, t, n)  (t *)alloc(a, sizeof(t), n)

typedef struct {
    char *beg, *end;
} arena;

static void *alloc(arena *a, ptrdiff_t size, ptrdiff_t count)
{
    ptrdiff_t available = a->end - a->beg;
    ptrdiff_t alignment = (uintptr_t)a->end & (sizeof(void *) - 1);
    if (count > (available - alignment)/size) {
        assert(0);
    }
    return memset(a->end -= alignment + count*size, 0, count*size);
}

typedef struct {
    uint8_t  *data;
    ptrdiff_t len;
} str;

static uint64_t hash(str s)
{
    // NOTE: for random inputs, hashing initial bytes is sufficient
    uint64_t h = -s.len;
    memcpy(&h, s.data, s.len<8?s.len:8);
    return h * 1111111111111111111u;
}

static _Bool equals(str a, str b)
{
    return a.len==b.len && (!a.len || !memcmp(a.data, b.data, a.len));
}

static str cuttail(str s, ptrdiff_t len)
{
    assert(len >= 0);
    assert(len <= s.len);
    if (s.data) {
        s.data += len;
        s.len -= len;
    }
    return s;
}

static str takehead(str s, ptrdiff_t len)
{
    assert(len >= 0);
    assert(len <= s.len);
    s.len = len;
    return s;
}

typedef struct set set;
struct set {
    set *child[4];
    str  key;
};

static _Bool insert(set **s, str key, arena *a)
{
    for (uint64_t h = hash(key); *s; h <<= 2) {
        if (equals(key, (*s)->key)) {
            return 0;
        }
        s = &(*s)->child[h>>62];
    }
    (*s = new(a, set, 1))->key = key;
    return 1;
}

static _Bool whitespace(uint8_t c)
{
    return c=='\t' || c=='\n' || c=='\r' || c==' ';
}

static _Bool digit(uint8_t c)
{
    return c>='0' && c<='9';
}

static str skipspace(str s)
{
    ptrdiff_t len = 0;
    for (; len<s.len && whitespace(s.data[len]); len++) {}
    return cuttail(s, len);
}

typedef struct {
    int value;
    str input;
} intresult;

static intresult readint(str s)
{
    s = skipspace(s);
    assert(s.len);

    intresult r = {0};
    ptrdiff_t len = 0;
    while (len<s.len && !whitespace(s.data[len])) {
        assert(digit(s.data[len]));
        r.value = r.value*10 + s.data[len++] - '0';
    }
    r.input = cuttail(s, len);
    return r;
}

static int *solve(str input, arena *a)
{
    intresult r = readint(input);
    int ntest = r.value;
    assert(ntest > 0);
    int *solution = new(a, int, ntest+1);

    for (int n = 0; n < ntest; n++) {
        r = readint(r.input);
        int strlen = r.value;
        assert(strlen > 0);

        r = readint(r.input);
        int keylen = r.value;
        assert(keylen > 0);
        assert(keylen <= strlen);

        r.input = skipspace(r.input);
        str line = takehead(r.input, strlen);
        r.input = cuttail(r.input, strlen);

        set *seen = 0;
        arena scratch = *a;
        for (ptrdiff_t i = 0; i < line.len-keylen+1; i++) {
            str key = takehead(cuttail(line, i), keylen);
            solution[n] += insert(&seen, key, &scratch);
        }
    }

    return solution;
}


// Platform
#include <stdio.h>
#include <stdlib.h>

#ifndef GENERATE

int main(void)
{
    ptrdiff_t cap = (ptrdiff_t)1<<26;
    arena a = {0};
    a.end = a.beg = malloc(cap);
    a.end += cap;

    str input = {0};
    input.data = (uint8_t *)a.beg;
    input.len = fread(input.data, 1, a.end-a.beg, stdin);
    a.beg += input.len;

    for (int *solution = solve(input, &a); *solution; solution++) {
        printf("%d\n", *solution);
    }
    fflush(stdout);
    return ferror(stdout);
}

#else  // GENERATE

static int32_t randint(uint64_t rng[1], int32_t lo, int32_t hi)
{
    *rng = *rng*0x3243f6a8885a308d + 1;
    return (int32_t)((((*rng>>32) * (hi - lo))>>32) + lo);
}

int main(void)
{
    uint64_t rng = 1;  // answer CRC32 with CR newlines: 7f1d3b69
    int ntests = randint(&rng, 40, 51);
    printf("%d\n", ntests);
    for (int i = 0; i < ntests; i++) {
        int strlen = randint(&rng, 10000, 100001);
        int keyexp = randint(&rng, 1, 6);
        int limit = 1;
        for (int e = 0; e < keyexp; e++) { limit *= 10; }
        int keylen;
        do {
            keylen = randint(&rng, 1, limit);
        } while (keylen > strlen);
        printf("%d %d\n", strlen, keylen);
        for (int i = 0; i < strlen; i++) {
            putchar("abcdefghijklmnopqrstuvwxyz"[randint(&rng, 0, 26)]);
        }
        putchar('\n');
    }
    fflush(stdout);
    return ferror(stdout);
}
#endif
