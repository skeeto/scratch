#include <stdio.h>
#include "int32trie.h"

static uint32_t
triple32(uint32_t x)
{
    x ^= x >> 17; x *= 0xed5ad4bb;
    x ^= x >> 11; x *= 0xac4c1b51;
    x ^= x >> 15; x *= 0x31848bab;
    x ^= x >> 14;
    return x;
}

static uint32_t
triple32_r(uint32_t x)
{
    x ^= x >> 14 ^ x >> 28; x *= 0x32b21703;
    x ^= x >> 15 ^ x >> 30; x *= 0x469e0db1;
    x ^= x >> 11 ^ x >> 22; x *= 0x79a85073;
    x ^= x >> 17;
    return x;
}

struct visitor {
    long long prev;
    uint32_t k;
};

static int
visit(int32_t k, int32_t v, void *arg)
{
    struct visitor *d = arg;

    if (k < d->prev) {
        printf("FAIL %ld < %ld\n", (long)k, (long)d->prev);
        return 1;
    }

    long i = triple32_r(k)^d->k;
    int expect = 1 + i%1000;
    if (v != expect) {
        printf("FAIL %ld != %d (visit)\n", (long)v, expect);
        return 1;
    }

    d->prev = k;
    return 0;
}

int
main(void)
{
    struct int32trie t[] = {{0, 0, 0}};

    for (int j = 0; j < 16; j++) {
        long n = 1L << (j + 6);
        uint32_t k = triple32(-n);

        for (long i = 0; i < n; i++) {
            int32trie_put(t, triple32(i^k), 1 + i%1000);
        }

        struct visitor d = {-2147483648LL, k};
        if (int32trie_visit(t, visit, &d)) {
            return 1;
        }

        for (long i = 0; i < n; i++) {
            int expect = 1 + i%1000;
            if (int32trie_get(t, triple32(i^k)) != expect) {
                printf("FAIL %08lx != %d\n", (long)triple32(i), expect);
                int32trie_reset(t);
                return 1;
            }
        }

        for (long i = n; i < n*2; i++) {
            if (int32trie_get(t, triple32(i))) {
                printf("FAIL %08lx != 0\n", (long)triple32(i));
                int32trie_reset(t);
                return 1;
            }
        }

        double mb = t->len * sizeof(t->nodes[0]) / 1048576.0;
        printf("trie %d\tnodes=%ld\tsize=%.3fMiB\n", j, n, mb);
        int32trie_reset(t);
    }
    puts("PASS");
    return 0;
}
