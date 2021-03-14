/* Boyer-Moore-Horspool bytestring search state machine
 *
 * Finds instances of a bytestring needle in an arbitrarily-large haystack
 * given just a byte at a time. Makes no memory allocations and only
 * requires scratch space the same size as the needle.
 *
 * This is free and unencumbered software released into the public domain.
 */
#include <stddef.h>

struct findmem {
    const void *needle;
    void *scratch;
    size_t len, cap, off;
    size_t table[256];
};

/* Initialize a state for a particular bytestring needle. Scratch space must
 * be as large as the needle. Both needle and scratch will be used during
 * the search.
 */
static void
findmem_init(struct findmem *f, const void *needle, size_t len, void *scratch)
{
    size_t i;
    const unsigned char *n = needle;
    f->needle = needle;
    f->scratch = scratch;
    f->cap = len;
    f->len = f->off = 0;
    for (i = 0; i < 256; i++) {
        f->table[i] = len;
    }
    for (i = 0; i < len; i++) {
        f->table[n[i]] = len - i - 1;
    }
}

/* Given the next byte from the haystack, return 1 if it completed a needle
 * match, otherwise return 0. Matches may overlap.
 */
static int
findmem(struct findmem *f, int byte)
{
    size_t i, j;
    unsigned char *s = f->scratch;
    const unsigned char *n = f->needle;

    s[(f->off + f->len) % f->cap] = byte;
    if (f->len < f->cap) {
        if (++f->len < f->cap) {
            return 0; /* circular buffer not yet filled */
        }
    } else {
        f->off = (f->off + 1) % f->cap;
    }

    for (i = f->cap - 1; i != (size_t)-1; i--) {
        j = (f->off + i) % f->cap;
        if (n[i] != s[j]) {
            /* discard part of the scratch buffer (skip) */
            f->len -= f->table[byte];
            f->off = (f->off + f->table[byte]) % f->cap;
            return 0;
        }
    }
    return 1;
}


#ifdef TEST
#include <stdio.h>

#define B64INIT(seed) {seed, 0}
#define B64 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
struct b64gen {
    unsigned long long s;
    int n;
};

static int
b64gen(struct b64gen *g)
{
    if (!g->n) {
        g->s = g->s*0x243f6a8885a308d3 + 1;
        g->n = 4;
    }
    return B64[g->s >> (32 + --g->n*8) & 0x3f];
}

int
main(void)
{
    struct b64gen g = B64INIT(0x13198a2e03707344);
    unsigned char needle[] = "xyzzy";
    long long expect[] = {0x8c06c28a, 0xb95d57e9, 0xbec756a4};
    int nexpect = (int)(sizeof(expect)/sizeof(*expect));
    int expecti = 0;

    struct findmem f[1];
    unsigned char scratch[sizeof(needle)];
    findmem_init(f, needle, sizeof(needle)-1, scratch);
    for (long long i = 0; i < 1LL<<32; i++) {
        if (findmem(f, b64gen(&g))) {
            if (expecti == nexpect) {
                printf("FAIL: matches %d, got %d\n", nexpect, expecti+1);
                return 1;
            }
            long long match = i - sizeof(needle) + 2;
            if (match != expect[expecti]) {
                printf("FAIL: want %llx, got %llx\n", expect[expecti], match);
                return 1;
            }
            expecti++;
        }
    }

    if (nexpect != expecti) {
        printf("FAIL: matches %d, only got %d\n", nexpect, expecti);
        return 1;
    }

    printf("PASS\n");
    return 0;
}

#endif /* TEST */
