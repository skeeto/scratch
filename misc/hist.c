/* Histogram of each input line, a la "sort | uniq -c".
 *
 * Usage:
 *   $ cc -O3 -march=native -o hist hist.c
 *   $ ./hist <input.txt >output.txt
 *
 * This is free and unencumbered software released into the public domain.
 */
#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

static void
die(void)
{
    fprintf(stderr, "hist: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
}

static void
dies(const char *s)
{
    fprintf(stderr, "hist: %s\n", s);
    exit(EXIT_FAILURE);
}

/* Like BSD reallocarray(), but abort on failure. */
static void *
xrealloc(void *p, size_t nmemb, size_t size)
{
    if (size && nmemb > (size_t)-1 / size)
        dies("out of memory");
    if (!(p = realloc(p, nmemb * size)))
        dies("out of memory");
    return p;
}

static uint64_t
load64le(const unsigned char *p)
{
    return (uint64_t)p[0] <<  0 |
           (uint64_t)p[1] <<  8 |
           (uint64_t)p[2] << 16 |
           (uint64_t)p[3] << 24 |
           (uint64_t)p[4] << 32 |
           (uint64_t)p[5] << 40 |
           (uint64_t)p[6] << 48 |
           (uint64_t)p[7] << 56;
}

static uint64_t
hash64(const void *buf, size_t len)
{
    /* TODO: Use keyed hash? */
    uint64_t h = 0x637f6e65916dff18;
    size_t nblocks = len / 8;
    const unsigned char *p = buf;
    const unsigned char *tail = p + nblocks * 8;

    for (size_t i = 0; i < nblocks; i++) {
        h += load64le(p + i * 8);
        h ^= h >> 30;
        h *= UINT64_C(0xbf58476d1ce4e5b9);
        h ^= h >> 27;
        h *= UINT64_C(0x94d049bb133111eb);
        h ^= h >> 31;
    }

    uint64_t rest = 0;
    switch (len % 8) {
        case 7: rest |= (uint64_t)tail[6] << 48;
        case 6: rest |= (uint64_t)tail[5] << 40;
        case 5: rest |= (uint64_t)tail[4] << 32;
        case 4: rest |= (uint64_t)tail[3] << 24;
        case 3: rest |= (uint64_t)tail[2] << 16;
        case 2: rest |= (uint64_t)tail[1] <<  8;
        case 1: rest |= (uint64_t)tail[0] <<  0;
                h += rest;
                h ^= h >> 32;
                h *= UINT64_C(0xd6e8feb86659fd93);
                h ^= h >> 32;
                h *= UINT64_C(0xd6e8feb86659fd93);
                h ^= h >> 32;
    }

    return h;
}

struct ht_entry {
    uint64_t hash;
    uint64_t count;
    size_t len;
    const void *ptr;
};

struct ht {
    size_t cap;
    size_t fill;
    size_t max;
    struct ht_entry *entries;
};

/* Initialize a hash table to a given power-of-two capacity.
 */
static void
ht_init(struct ht *ht, size_t cap)
{
    ht->cap = cap;
    ht->fill = 0;
    ht->max = ht->cap * 4 / 5;
    ht->entries = xrealloc(0, ht->cap, sizeof(ht->entries[0]));
    for (size_t i = 0; i < ht->cap; i++)
        ht->entries[i].ptr = 0;
}

/* Return the hash table entry for the given buffer.
 */
static struct ht_entry *
ht_find(struct ht *ht, const void *ptr, size_t len)
{
    size_t mask = ht->cap - 1;
    uint64_t hash = hash64(ptr, len);
    size_t i = hash & mask;
    for (;;) {
        struct ht_entry *e = ht->entries + i;
        if (!e->ptr) {
            e->ptr = ptr;
            e->len = len;
            e->hash = hash;
            e->count = 0;
            ht->fill++;
            return e;
        }
#ifdef FUZZY
        /* Hope there are no hash collisions! */
        if (e->hash == hash && e->len == len)
            return e;
#else
        if (e->hash == hash && e->len == len && !memcmp(e->ptr, ptr, len))
            return e;
#endif
        i = (i + 1) & mask;
    }
}

/* Double the capacity of the hash table.
 */
static void
ht_grow(struct ht *ht)
{
    struct ht new;
    ht_init(&new, ht->cap * 2);
    new.fill = ht->fill;

    uint64_t mask = new.cap - 1;
    for (size_t i = 0; i < ht->cap; i++) {
        struct ht_entry *e = ht->entries + i;
        if (e->ptr) {
            size_t ni = e->hash & mask;
            for (;;) {
                struct ht_entry *n = new.entries + ni;
                if (!n->ptr) {
                    *n = *e;
                    break;
                }
                ni = (ni + 1) & mask;
            }
        }
    }

    free(ht->entries);
    *ht = new;
}

/* Increment the entry for the given buffer, adding it to the table if
 * necessary. The table will automatically grow if needed.
 */
static void
ht_inc(struct ht *ht, const void *ptr, size_t len)
{
    struct ht_entry *e = ht_find(ht, ptr, len);
    e->count++;
    if (ht->fill > ht->max)
        ht_grow(ht);
}

/* Used by ht_sort().
 */
static int
ht_cmp(const void *a, const void *b)
{
    const struct ht_entry *ea = a;
    const struct ht_entry *eb = b;

    /* Sort NULL to the end */
    if (!ea->ptr && !eb->ptr) return 0;
    if (!ea->ptr) return +1;
    if (!eb->ptr) return -1;

    size_t len = eb->len < ea->len ? eb->len : ea->len;
    int r = memcmp(ea->ptr, eb->ptr, len);
    if (!r && ea->len < eb->len)
        return -1;
    else if (!r && ea->len > eb->len)
        return +1;
    return r;
}

/* Sort the hash table entries putting NULLs at the end.
 * This effectively destroys the hash table.
 */
static void
ht_sort(struct ht *ht)
{
    qsort(ht->entries, ht->cap, sizeof(ht->entries[0]), ht_cmp);
}

int
main(void)
{
    size_t len;
    unsigned char *buf;

    /* Input must be a file so we can memory map it. */

    struct stat stat;
    if (fstat(0, &stat))
        die();
    len = stat.st_size;
    if (stat.st_size != (off_t)len)
        dies("input too large");

    buf = mmap(0, len, PROT_READ, MAP_PRIVATE, 0, 0);
    if (buf == MAP_FAILED)
        die();

    /* This makes some things simpler. */
    if (buf[len - 1] != '\n')
        dies("input doesn't end with a newline");

    struct ht ht[1];
    ht_init(ht, 1024);

    unsigned char *ptr = buf;
    size_t rem = len;
    while (rem) {
        unsigned char *end = memchr(ptr, '\n', rem);
        ht_inc(ht, ptr, end - ptr);
        rem -= end - ptr + 1;
        ptr = end + 1;
        (void)ht_inc;
    }

    ht_sort(ht);
    for (size_t i = 0; i < ht->fill; i++) {
        struct ht_entry *e = ht->entries + i;
        printf("%-21llu", (unsigned long long)e->count);
        fwrite(e->ptr, e->len + 1, 1, stdout);
    }
    if (fflush(stdout))
        die();
}
