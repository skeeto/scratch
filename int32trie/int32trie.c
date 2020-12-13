/* This is free and unencumbered software released into the public domain. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "int32trie.h"

static uint32_t
int32trie_new(struct int32trie *t)
{
    if (t->len == t->cap) {
        uint32_t cap = t->cap ? t->cap *= 2: 8;
        if (!cap || !(cap*sizeof(t->nodes[0]))) {
            return -1;
        }
        void *p = realloc(t->nodes, cap*sizeof(t->nodes[0]));
        if (!p) {
            return -1;
        }
        t->cap = cap;
        t->nodes = p;
    }
    uint32_t i = t->len++;
    memset(&t->nodes[i], 0, sizeof(t->nodes[i]));
    return i;
}

int32_t
int32trie_get(const struct int32trie *t, int32_t k)
{
    if (!t->len) return 0;
    uint32_t u = k;
    uint32_t n = 0;
    for (int i = 7; i >= 1; i--) {
        int c = u >> (i*4) & 0xf;
        if (i == 7) c = (c + 8) % 16;
        n = t->nodes[n].child[c];
        if (!n) return 0;
    }
    return t->nodes[n].child[u&0xf];
}

int
int32trie_put(struct int32trie *t, int32_t k, int32_t v)
{
    if (!t->len && int32trie_new(t)) {
        return 0;
    }
    uint32_t u = k;
    uint32_t n = 0;
    for (int i = 7; i >= 1; i--) {
        int c = u >> (i*4) & 0xf;
        if (i == 7) c = (c + 8) % 16;
        uint32_t m = t->nodes[n].child[c];
        if (!m) {
            m = int32trie_new(t);
            if (m == (uint32_t)-1) {
                return 0;
            }
            t->nodes[n].child[c] = m;
        }
        n = m;
    }
    t->nodes[n].child[u&0xf] = v;
    return 1;
}

void
int32trie_reset(struct int32trie *t)
{
    free(t->nodes);
    t->cap = t->len = 0;
    t->nodes = 0;
}

int
int32trie_visit(const struct int32trie *t, int32trie_visitor f, void *arg)
{
    int z = 1;
    struct {
        uint32_t n;
        uint32_t k;
        int i;
    } stack[8];
    stack[0].n = 0;
    stack[0].k = 0;
    stack[0].i = 0;

    while (z) {
        uint32_t n = stack[z-1].n;
        uint32_t k = stack[z-1].k;

        int i = stack[z-1].i++;
        if (i == 16) {
            z--;
            continue;
        }

        uint32_t c = t->nodes[n].child[i];
        if (c) {
            if (z < 8) {
                if (z == 1) i = (i + 8) % 16;
                stack[z].n = c;
                stack[z].k = k | (uint32_t)i<<((8-z)*4);
                stack[z].i = 0;
                z++;
            } else {
                int r = f(k | i, c, arg);
                if (r) return r;
            }
        }
    }

    return 0;
}
