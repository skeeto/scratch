// A compact, single function string-to-string hash map
// Ref: https://old.reddit.com/r/C_Programming/comments/18iwhw0
// Ref: https://nullprogram.com/blog/2023/10/05/
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Initialization: Call with null key and heaplen. A heap can have only
// one hashmap, and all alloctions will come from this heap. The heap
// must be pointer-aligned and have space for at least 3 pointers.
//
// Upsert: Pass both a key and heaplen. Returns a pointer to the value
// which you can populate. Stores a copy of the key in the map, and
// updates *heaplen on allocation. Returns null for out-of-memory.
//
// Lookup: Pass null for heaplen, which inhibits allocation. Returns
// null if no such entry exists.
//
// Iterate (insertion order): Pass a null key and heaplen==heap to
// retrieve the first key pointer. Use this key with heaplen==heap to
// retrieve the next key. Returns null for the final key. You _must_ use
// the returned key pointer during iteration, not a copy of the key.
// Iteration has no internal state and can occur concurrently.
//
// Delete: Lookup and set the value to a gravestone of your choice.
char **hashmap(char *key, void *heap, ptrdiff_t *heaplen)
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
    } *map = heap;

    if (!key && !heaplen) {  // init
        map->root = map->head = 0;
        map->tail = &map->head;
        return 0;
    } else if (!key && heaplen==heap) {  // first key
        return map->head ? &map->head->key : 0;
    } else if (heaplen == heap) {  // next key
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
    if (!heaplen) return 0;  // lookup failed

    ptrdiff_t total = sizeof(node) + keylen + (-keylen&(sizeof(void *)-1));
    if (*heaplen-(ptrdiff_t)sizeof(*map) < total) {
        return 0;  // out of memory
    }
    *n = (node *)((char *)heap + (*heaplen -= total));
    memset(*n, 0, sizeof(node));
    (*n)->key = (char *)*n + sizeof(node);
    memcpy((*n)->key, key, keylen);
    *map->tail = *n;
    map->tail = &(*n)->next;
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

    for (char **k = hashmap(0, heap, heap); k; k = hashmap(*k, heap, heap)) {
        printf("k:%s\tv:%s\n", *k, *hashmap(*k, heap, 0));
    }

    free(heap);  // destroy the hashmap
}

#elif defined(BENCH)
#include <stdlib.h>

int main(void)
{
    ptrdiff_t len = 1<<28;
    void *heap = malloc(len);
    hashmap(0, heap, 0);

    char key[8] = {0};
    for (int i = 0; i < 1000000; i++) {
        char *end = key + 7;
        int t = i;
        do *--end = (char)(t%10) + '0';
        while (t /= 10);
        *hashmap(end, heap, &len) = (char *)(intptr_t)i;
    }

    int i = 0;
    for (char **k = hashmap(0, heap, heap); k; k = hashmap(*k, heap, heap)) {
        char *value = *hashmap(*k, heap, 0);
        if ((intptr_t)value != i++) {
            *(volatile int *)0 = 0;
        }
    }
}
#endif
