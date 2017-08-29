/* C99 32-bit closed hashing integer hash set header library
 *
 * This is free and unencumbered software released into the public domain.
 *
 * It's up to the caller to allocate and zero-initialize the table. The
 * set32_z() function assists in choosing a table size, which must be a
 * power of 2. This hash set cannot store the integer 0.
 *
 * To get the implementation, define SET32_IMPLEMENTATION before
 * including this file. Optionally define SET32_API to control linkage.
 */
#ifndef SET32_H
#define SET32_H

#include <stdint.h>

#ifndef SET32_API
#  define SET32_API static
#endif

/* Compute a power of two table size from a maximum number of elements */
SET32_API
int set32_z(uint32_t max);

/* 32-bit hash function */
SET32_API
uint32_t set32_hash(uint32_t);

/* Insert an integer into the set, which may already be present */
SET32_API
void set32_insert(uint32_t *table, int z, uint32_t v);

/* Remove an integer, which may not actually be present in the set */
SET32_API
void set32_remove(uint32_t *table, int z, uint32_t v);

/* Check set membership of an integer */
SET32_API
int set32_contains(uint32_t *table, int z, uint32_t v);

#ifdef SET32_IMPLEMENTATION

SET32_API
int
set32_z(uint32_t n)
{
    int z = 0;
    while (UINT32_C(1) << z < n * 3 / 2)
        z++;
    return z;
}

SET32_API
uint32_t
set32_hash(uint32_t a)
{
    a = (a ^ UINT32_C(61)) ^ (a >> 16);
    a = a + (a << 3);
    a = a ^ (a >> 4);
    a = a * UINT32_C(0x27d4eb2d);
    a = a ^ (a >> 15);
    return a;
}

SET32_API
void
set32_insert(uint32_t *table, int z, uint32_t v)
{
    uint32_t mask = (UINT32_C(1) << z) - 1;
    uint32_t i = set32_hash(v) & mask;
    while (table[i] && table[i] != v)
        i = (i + 1) & mask;
    if (!table[i])
        table[i] = v;
}

SET32_API
void
set32_remove(uint32_t *table, int z, uint32_t v)
{
    uint32_t mask = (UINT32_C(1) << z) - 1;
    uint32_t i = set32_hash(v) & mask;
    while (table[i] && table[i] != v)
        i = (i + 1) & mask;
    if (table[i]) {
        table[i] = 0;
        for (i = (i + 1) & mask; table[i]; i = (i + 1) & mask) {
            v = table[i];
            table[i] = 0;
            set32_insert(table, z, v);
        }
    }
}

SET32_API
int
set32_contains(uint32_t *table, int z, uint32_t v)
{
    uint32_t mask = (UINT32_C(1) << z) - 1;
    uint32_t i = set32_hash(v) & mask;
    while (table[i] && table[i] != v)
        i = (i + 1) & mask;
    return !!table[i];
}

#endif /* SET32_IMPLEMENTATION */
#endif /* SET32_H */
