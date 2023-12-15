// A compact, single function string-to-string hash map
// Ref: https://old.reddit.com/r/C_Programming/comments/18iwhw0
// Ref: https://nullprogram.com/blog/2023/10/05/
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define NEXT ((ptrdiff_t *)(uintptr_t)-1)

// Initialization: Call with null key and len. A heap can have only one
// table, and all alloctions will come from this heap. The heap must be
// pointer-aligned and have room for at least 3 pointers.
//
// Upsert: Pass both a key and the len. Returns a pointer to the value
// which you can populate. Stores a copy of the key in the table, and
// len is updated on allocation. Returns null on allocation failure.
//
// Lookup: Pass null for len. Returns null if no such entry exists.
//
// Iterate (insertion order): First pass a null key and NEXT for the len
// pointer. Returns a pointer to the first key. Use this key with NEXT
// to get the next key. Returns null for the final key. You *must* use
// the returned key pointer during iteration, not a copy of the key.
//
// Delete: Lookup and set the value to a gravestone of your choice.
char **hashmap(char *key, void *heap, ptrdiff_t *len)
{
    typedef struct node node;
    struct node {
        node *child[4];
        node *next;
        char *key;
        char *value;
    } **n = heap;
    struct {
        node  *root;
        node  *head;
        node **tail;
    } *table = heap;

    if (!key && !len) {  // init
        table->root = table->head = 0;
        table->tail = &table->head;
        return 0;
    } else if (!key && len==NEXT) {  // first key
        return table->head ? &table->head->key : 0;
    } else if (len == NEXT) {  // next key
        node *next = ((node *)(key - sizeof(node)))->next;
        return next ? &next->key : 0;
    }

    uint64_t h = 0x100;
    ptrdiff_t keylen = 0;
    for (; key[keylen++]; h *= 1111111111111111111u) {
        h ^= key[keylen] & 255;
    }
    for (; *n; h <<= 2) {
        if (!strcmp(key, (*n)->key)) {
            return &(*n)->value;
        }
        n = &(*n)->child[h>>62];
    }
    if (!len) return 0;  // lookup failed

    ptrdiff_t total = sizeof(node) + keylen + (-keylen&(sizeof(void *)-1));
    if (*len-(ptrdiff_t)sizeof(*table) < total) {
        return 0;  // out of memory
    }
    *n = (node *)((char *)heap + (*len -= total));
    memset(*n, 0, sizeof(node));
    (*n)->key = (char *)*n + sizeof(node);
    memcpy((*n)->key, key, keylen);
    *table->tail = *n;
    table->tail = &(*n)->next;
    return &(*n)->value;
}


#ifdef DEMO
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    ptrdiff_t len = 1<<16;
    void *heap = malloc(len);
    hashmap(0, heap, 0);

    *hashmap("hello", heap, &len) = "world";
    *hashmap("foo", heap, &len) = "bar";
    puts(*hashmap("foo", heap, 0));
    puts(*hashmap("hello", heap, 0));

    for (char **k = hashmap(0, heap, NEXT); k; k = hashmap(*k, heap, NEXT)) {
        printf("k:%s\tv:%s\n", *k, *hashmap(*k, heap, 0));
    }

    free(heap);  // destroy the table
}
#endif
