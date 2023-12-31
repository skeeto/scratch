// A compact, single function string-to-string hash map
// Ref: https://old.reddit.com/r/C_Programming/comments/18iwhw0
// Ref: https://nullprogram.com/blog/2023/10/05/
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Initialization: Call with null key. A heap can have only one map at a
// time, and all alloctions will come from this heap. The heap must be
// pointer-aligned and have space for at least two pointers.
//
// Upsert: Pass both a key and heaplen. Returns a pointer to the value
// which you can populate. Stores a copy of the key in the map, and
// updates *heaplen on allocation. Returns null for out-of-memory.
//
// Lookup: Pass null for heaplen, which inhibits allocation. Returns
// null if no such entry exists.
//
// Iterate (insertion order): Pass a null key and heaplen==heap to get
// the first key pointer. Use this key with heaplen==heap to retrieve
// the next key. Returns null from the final key. You _must_ use the
// returned key during iteration, not a copy. Iteration has no internal
// state and can occur concurrently. The return value is a key/value
// tuple and the value is at the second index.
//
// Delete: Lookup and set the value to a gravestone of your choice.
char **hashmap(char *key, void *heap, ptrdiff_t *heaplen)
{
    enum { ARY=2 };  // 1=slowest+small, 2=faster+larger, 3=fastest+large
    typedef struct node node;
    struct node {
        node *child[1<<ARY];
        node *next;
        char *key;
        char *value;
    };
    struct {
        node  *head;
        node **tail;
    } *map = heap;

    if (!key && heaplen!=heap) {  // init
        *heaplen &= -sizeof(void *);  // align high end
        map->head = 0;
        map->tail = &map->head;
        return 0;
    } else if (!key && heaplen==heap) {  // first key
        return map->head ? &map->head->key : 0;
    } else if (heaplen == heap) {  // next key
        node *next = ((node *)(key - sizeof(node)))->next;
        return next ? &next->key : 0;
    }

    uint64_t hash = 0x100;
    ptrdiff_t keylen = 0;
    for (; key[keylen++]; hash *= 0x100000001b3) {
        hash ^= key[keylen] & 255;
    }

    node **n = &map->head;
    for (; *n; hash <<= ARY) {
        if (!strcmp(key, (*n)->key)) {
            return &(*n)->value;
        }
        n = &(*n)->child[hash>>(64 - ARY)];
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
    hashmap(0, heap, &len);

    *hashmap("hello", heap, &len) = "world";
    *hashmap("foo", heap, &len) = "bar";
    puts(*hashmap("foo", heap, 0));
    puts(*hashmap("hello", heap, 0));

    for (char **e = 0; (e = hashmap(e?*e:0, heap, heap));) {
        printf("k:%s\tv:%s\n", e[0], e[1]);
    }

    free(heap);  // destroy the hashmap
}

#elif defined(BENCH)
#include <stdlib.h>

int main(void)
{
    ptrdiff_t len = 1<<28;
    void *heap = malloc(len);
    hashmap(0, heap, &len);

    char key[8] = {0};
    for (int i = 0; i < 1000000; i++) {
        char *end = key + 7;
        int t = i;
        do *--end = (char)(t%10) + '0';
        while (t /= 10);
        *hashmap(end, heap, &len) = (char *)(intptr_t)i;
    }

    int i = 0;
    for (char **e = 0; (e = hashmap(e?*e:0, heap, heap));) {
        if ((intptr_t)e[1] != i++) {
            *(volatile int *)0 = 0;
        }
    }
}
#endif
