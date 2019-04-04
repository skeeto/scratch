/* stream tokenizer: strtok() for ANSI C file streams
 *
 * This provides getdelim()-like functionality, but it is faster than
 * your system's detdelim() or getline(). The interface is a bit
 * different in order to accomodate its own input buffer.
 *
 * This file can be compiled as either C or C++.
 *
 * For the best performance, disable libc stream buffering:
 *     setvbuf(stream, 0, _IONBF, 0);
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/**
 * Initialize a context for reading tokens from STREAM.
 *
 * Returns non-zero on success.
 */
int
streamtok_init(struct streamtok *ctx, int delim, FILE *stream)
{
    ctx->cap = 4096;
    ctx->len = 0;
    ctx->off = 0;
    ctx->buf = (char *)malloc(ctx->cap);
    ctx->stream = stream;
    ctx->delim = delim;
    return !!ctx->buf;
}

/**
 * Destroy a context.
 */
void
streamtok_free(struct streamtok *ctx)
{
    free(ctx->buf);
    ctx->buf = 0;
}

/**
 * Try to get another token from the stream.
 *
 * Returned tokens are not NUL-terminated and includes the delimeter.
 * You can modify the returned buffer (e.g. strtok()), but it will be
 * invalid after the next call.
 *
 * STREAMTOK_OK:    A token was successfully found.
 * STREAMTOK_EOF:   No more input, no token returned.
 * STREAMTOK_OOM:   Not enough memory, no token returned. (recoverable)
 * STREAMTOK_ERROR: Input error, returns partial token up until error.
 */
enum streamtok_result
streamtok_next(struct streamtok *ctx, char **tokptr, size_t *len)
{
    size_t n;
    char *beg;
    char *end;

    for (;;) {
        beg = ctx->buf + ctx->off;
        end = (char *)memchr((void *)beg, ctx->delim, ctx->len - ctx->off);

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
            if (cap < ctx->cap || !(buf = (char *)realloc(ctx->buf, cap))) {
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

/* EXAMPLE  */

int
main(void)
{
    struct streamtok ctx[1];
    streamtok_init(ctx, '\n', stdin);
    setvbuf(stdin, 0, _IONBF, 0);

    for (;;) {
        char *line;
        size_t len;
        switch (streamtok_next(ctx, &line, &len)) {
            case STREAMTOK_EOF:
                streamtok_free(ctx);
                return 0;
            case STREAMTOK_OOM:
                fprintf(stderr, "fatal: out of memory\n");
                return 1;
            case STREAMTOK_ERROR:
                fprintf(stderr, "fatal: input error\n");
                return 1;
            case STREAMTOK_OK:
                printf("%2zu ", len);
                fwrite(line, len, 1, stdout);
        }
    }
}
