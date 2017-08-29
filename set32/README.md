# C99 32-bit integer hash set header library

This is a public domain header library defining a fast, lightweight
integer hash set. It uses closed hashing and makes no allocations of its
own. The API is dead simple:

~~~c
int      set32_z(uint32_t max);
uint32_t set32_hash(uint32_t);
void     set32_insert(uint32_t *table, int z, uint32_t v);
void     set32_remove(uint32_t *table, int z, uint32_t v);
int      set32_contains(uint32_t *table, int z, uint32_t v);
~~~

The `set32_z()` function returns the appropriate power-of-two table size
for the given maximum number of set elements. It's up to the caller to
allocate and zero-initialize this buffer. The hash set is unable to
store the value 0.
