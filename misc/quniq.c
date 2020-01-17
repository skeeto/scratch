/* Like "sort -u" or "sort | uniq" but much faster.
 * Inspired by Huniq2.
 * This is free and unencumbered software released into the public domain.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
oom(void)
{
    fprintf(stderr, "fatal: out of memory\n");
    exit(EXIT_FAILURE);
}

static uint64_t
hash(const void *buf, size_t len)
{
    size_t nblocks = len / 8;
    const unsigned char *p = buf;
    uint64_t h = 0xea24ccba9c7903c6;
    for (size_t i = 0; i < nblocks; i++) {
        uint64_t x;
        memcpy(&x, p + i*8, sizeof(x));
        h ^= x;
        h *= 0x9492da799b90d331;
    }

    p += nblocks*8;
    for (size_t i = 0; i < len%8; i++) {
        h ^= p[i];
        h *= 0x85120a0afdd7ee37;
    }
    return h ^ (h >> 32);
}

struct streamtok {
    char *buf;
    FILE *stream;
    size_t cap;
    size_t len;
    size_t off;
    int delim;
};

enum streamtok_result {
    STREAMTOK_OK, STREAMTOK_EOF, STREAMTOK_OOM, STREAMTOK_ERROR
};

static int
streamtok_init(struct streamtok *ctx, int delim, FILE *stream)
{
    ctx->cap = 4096;
    ctx->len = 0;
    ctx->off = 0;
    ctx->buf = malloc(ctx->cap);
    ctx->stream = stream;
    ctx->delim = delim;
    return !!ctx->buf;
}

static enum streamtok_result
streamtok_next(struct streamtok *ctx, char **tokptr, size_t *len)
{
    size_t n;
    char *beg;
    char *end;

    for (;;) {
        beg = ctx->buf + ctx->off;
        end = memchr(beg, ctx->delim, ctx->len - ctx->off);

        if (end) {
            ctx->off += end - beg + 1;
            *tokptr = beg;
            *len = end - beg + 1;
            return STREAMTOK_OK;
        }

        /* Toss contents before current offset */
        memmove(ctx->buf, ctx->buf + ctx->off, ctx->len - ctx->off);
        ctx->len -= ctx->off;
        ctx->off = 0;

        if (ctx->len == ctx->cap) {
            /* Buffer full, expand it */
            char *buf;
            size_t cap = ctx->cap * 2;
            if (cap < ctx->cap || !(buf = realloc(ctx->buf, cap))) {
                *tokptr = 0;
                *len = 0;
                return STREAMTOK_OOM;
            }
            ctx->cap = cap;
            ctx->buf = buf;
        }

        /* Load more data */
        n = fread(ctx->buf + ctx->len, 1, ctx->cap - ctx->len, ctx->stream);
        if (!n) {
            *tokptr = ctx->buf;
            *len = ctx->len;
            ctx->len = 0;
            if (ferror(ctx->stream))
                return STREAMTOK_ERROR;
            if (feof(ctx->stream))
                return *len ? STREAMTOK_OK : STREAMTOK_EOF;
        }
        ctx->len += n;
    }
}

struct strbuf {
    size_t len;
    size_t cap;
    char buf[];
};

static struct strbuf *
strbuf_create(void)
{
    size_t init = 1L << 20;
    struct strbuf *sb = malloc(sizeof(*sb) + init);
    sb->len = 0;
    sb->cap = init;
    return sb;
}

static struct strbuf *
strbuf_append(struct strbuf *sb, const char *s, size_t len)
{
    while (sb->len + len > sb->cap) {
        if (sb->cap * 2 == 0) {
            return 0; // size_t overflow
        }
        if (!(sb = realloc(sb, sizeof(*sb) + sb->cap*2))) {
            return 0; // OOM
        }
        sb->cap *= 2;
    }
    memcpy(sb->buf + sb->len, s, len);
    sb->len += len;
    return sb;
}

struct table {
    size_t len;
    size_t cap;
    struct {
        size_t off;
        size_t len;
    } *slots;
};

static int
table_init(struct table *t, size_t cap)
{
    t->len = 0;
    t->cap = cap ? cap : 1L << 20;
    t->slots = calloc(sizeof(t->slots[0]), t->cap);
    return t->slots ? 1 : 0;
}

static size_t
table_find(struct table *t, struct strbuf *sb, const char *s, size_t len)
{
    size_t mask = t->cap - 1;
    uint64_t h = hash(s, len);
    size_t i = h & mask;
    for (;;) {
        if (!t->slots[i].len) {
            /* Entry doesn't exist in the table */
            if (t->len > t->cap / 2) {
                /* Expand table to make space for new entry */
                struct table new;
                if (t->cap * 2 == 0 || !table_init(&new, t->cap * 2)) {
                    return -1; // OOM
                }
                for (size_t j = 0; j < t->cap; j++) {
                    size_t len = t->slots[j].len;
                    if (len) {
                        size_t off = t->slots[j].off;
                        char *key = sb->buf + off;
                        size_t dst = table_find(&new, sb, key, len);
                        new.slots[dst].off = off;
                        new.slots[dst].len = len;
                    }
                }
                free(t->slots);
                *t = new;
                /* Retry with the new table */
                return table_find(t, sb, s, len);
            } else {
                t->len++;
                return i; // Return the empty slot
            }
        }

        char *key = sb->buf + t->slots[i].off;
        if (t->slots[i].len == len && !memcmp(key, s, len)) {
            return i;
        }
        i = (i + 1) & mask;
    }
}

int
main(void)
{
    struct table ht[1];
    if (!table_init(ht, 0)) oom();

    struct strbuf *sb = strbuf_create();
    if (!sb) oom();

    struct streamtok ctx[1];
    if (!streamtok_init(ctx, '\n', stdin)) oom();
    setvbuf(stdin, 0, _IONBF, 0);

    for (;;) {
        char *line;
        size_t i, len;
        switch (streamtok_next(ctx, &line, &len)) {
        case STREAMTOK_EOF:
            if (!fwrite(sb->buf, sb->len, 1, stdout)) {
                return EXIT_FAILURE;
            }
            /* NOTE: intentionally not freeing memory before exit */
            return EXIT_SUCCESS;
        case STREAMTOK_OOM:
            oom();
            break;
        case STREAMTOK_ERROR:
            fprintf(stderr, "fatal: input error\n");
            return EXIT_FAILURE;
        case STREAMTOK_OK:
            i = table_find(ht, sb, line, len);
            if (i == (size_t)-1) {
                oom();
            }
            if (!ht->slots[i].len) {
                ht->slots[i].off = sb->len;
                ht->slots[i].len = len;
                sb = strbuf_append(sb, line, len);
                if (!sb) oom();
            }
        }
    }
}
