# int32 trie with int32 values

This C99 library implements a 32-bit trie with a depth of 8 (i.e. one
nibble per node). It stores one non-zero 32-bit value per key. All nodes
are allocated from a single, large allocation.

```c
int32_t int32trie_get(const struct int32trie *, int32_t k);
int     int32trie_put(struct int32trie *, int32_t k, int32_t v);
void    int32trie_reset(struct int32trie *);
int     int32trie_visit(const struct int32trie *, int32trie_visitor, void *);
```

Full documentation is in the header file.
