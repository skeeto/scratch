/* JSON builder: zero-allocation JSON serialization
 *
 * Input pointers and lengths must be valid, but otherwise the library
 * will detect all other errors (stack overflow, invalid call sequence,
 * invalid numbers, buffer exhausted).
 *
 * Ref: https://github.com/lcsmuller/json-build
 * Ref: https://old.reddit.com/r/C_Programming/comments/sf95m3/
 *
 * This is free and unencumbered software released into the public domain.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef JSONB_MAX_DEPTH
#  define JSONB_MAX_DEPTH 256
#endif

/* Must initialize offset, depth, and stack[0] to zero. */
#define JSONB_INIT {0}
struct jsonb {
    size_t offset;
    size_t depth;
    unsigned char stack[JSONB_MAX_DEPTH];
};

/* Evaluates to true if JSON buffer is complete. */
#define JSONB_DONE(b) (((b).depth == 0) && ((b).stack[0] == 6))

/* The output buffer and jsonb state are left entirely unmodified when
 * an error occurs. JSONB_BUFFER may occur before the buffer is fully
 * filled. If the buffer is resized, the operation must be retried.
 */
enum jsonb_result {
    JSONB_SUCCESS,  /* operation successful    */
    JSONB_BUFFER,   /* output buffer too small */
    JSONB_OVERFLOW, /* nesting level too deep  */
    JSONB_INVALID   /* invalid call sequence   */
};

/* Implementation notes
 *
 * No modifications may be made to any inputs along any path prior to an
 * error return. This ensures the inputs are not modified it something
 * is wrong.
 *
 * Stack state descriptions
 *   0: top-level fresh, nothing yet appended
 *   1: just inside object, either first key or object end
 *   2: at object value
 *   3: either at next object key or object end
 *   4: at first object in array
 *   5: beyond first object in array
 *   6: top-level complete, no more may be appended
 */

/* Begin writing an object into the buffer.
 *
 * Next operation should be one of:
 *
 * - jsonb_push_string()  (to write a key)
 * - jsonb_pop_object()
 *
 * Otherwise it returns JSONB_INVALID. Similarly, each string key should
 * be paired with a JSON value.
 */
static enum jsonb_result
jsonb_push_object(struct jsonb *b, char *buf, size_t len)
{
    if (b->depth == JSONB_MAX_DEPTH-1) {
        return JSONB_OVERFLOW;
    }

    switch (b->stack[b->depth]) {
    default: return JSONB_INVALID;
    case  0: if (b->offset+0 >= len) return JSONB_BUFFER;
             b->stack[b->depth++] = 6;
             break;
    case  2: if (b->offset+0 >= len) return JSONB_BUFFER;
             b->stack[b->depth++] = 3;
             break;
    case  4: if (b->offset+0 >= len) return JSONB_BUFFER;
             b->stack[b->depth++] = 5;
             break;
    case  5: if (b->offset+1 >= len) return JSONB_BUFFER;
             buf[b->offset++] = ',';
             b->depth++;
    }

    buf[b->offset++] = '{';
    b->stack[b->depth] = 1;
    return JSONB_SUCCESS;
}

/* Finish writing an object into the buffer. This cannot be called
 * immediately after writing a key, otherwise it return JSONB_INVALID.
 */
static enum jsonb_result
jsonb_pop_object(struct jsonb *b, char *buf, size_t len)
{
    if (b->depth == 0) {
        return JSONB_INVALID;
    }

    switch (b->stack[b->depth]) {
    default: return JSONB_INVALID;
    case  1:
    case  3: if (b->offset+0 >= len) return JSONB_BUFFER;
             b->depth--;
    }

    buf[b->offset++] = '}';
    return JSONB_SUCCESS;
}

/* Begin writing an array into the buffer. */
static enum jsonb_result
jsonb_push_array(struct jsonb *b, char *buf, size_t len)
{
    if (b->depth == JSONB_MAX_DEPTH-1) {
        return JSONB_OVERFLOW;
    }

    switch (b->stack[b->depth]) {
    default: return JSONB_INVALID;
    case  0: if (b->offset+0 >= len) return JSONB_BUFFER;
             b->stack[b->depth++] = 6;
             break;
    case  2: if (b->offset+0 >= len) return JSONB_BUFFER;
             b->stack[b->depth++] = 3;
             break;
    case  4: if (b->offset+0 >= len) return JSONB_BUFFER;
             b->stack[b->depth++] = 5;
             break;
    case  5: if (b->offset+1 >= len) return JSONB_BUFFER;
             buf[b->offset++] = ',';
             b->depth++;
    }

    buf[b->offset++] = '[';
    b->stack[b->depth] = 4;
    return JSONB_SUCCESS;
}

/* Finish writing an array into the buffer. */
static enum jsonb_result
jsonb_pop_array(struct jsonb *b, char *buf, size_t len)
{
    if (b->depth == 0) {
        return JSONB_INVALID;
    }

    switch (b->stack[b->depth]) {
    default: return JSONB_INVALID;
    case  4:
    case  5: if (b->offset+0 >= len) return JSONB_BUFFER;
             b->depth--;
    }

    buf[b->offset++] = ']';
    return JSONB_SUCCESS;
}

/* Insert a string or object key into the buffer.
 *
 * If slen is -1, compute the length from the null-terminator. Otherwise
 * the string need not be null-terminated. The string pointer may even
 * be NULL if slen is zero.
 *
 * Input is assumed to be valid UTF-8. Otherwise it will be garbage-in,
 * garbage-out, though always safely in bounds.
 *
 * Special characters in the string are automatically escaped for JSON.
 */
static enum jsonb_result
jsonb_push_string(struct jsonb *b, char *buf, size_t len, char *s, size_t slen)
{
    static const unsigned char lens[] = {
        6,6,6,6,6,6,6,6,2,2,2,6,2,2,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
        1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
    };
    int colon = 0;
    size_t i, n = 2;

    if (slen == (size_t)-1) {
        slen = strlen(s);
    }

    /* Compute the serialized string length using a lookup table */
    for (i = 0; i < slen; i++) {
        n += lens[s[i]&0xff];
    }

    switch (b->stack[b->depth]) {
    default: return JSONB_INVALID;
    case  0: if (b->offset+n >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 6;
             break;
    case  1: if (b->offset+n+1 >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 2;
             colon = 1;
             break;
    case  2: if (b->offset+n >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 3;
             break;
    case  3: if (b->offset+n+1 >= len) return JSONB_BUFFER;
             buf[b->offset++] = ',';
             b->stack[b->depth] = 2;
             colon = 1;
             break;
    case  4: if (b->offset+n >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 5;
             break;
    case  5: if (b->offset+n+1 >= len) return JSONB_BUFFER;
             buf[b->offset++] = ',';
    }

    /* JSON-encode the string */
    buf[b->offset++] = '"';
    for (i = 0; i < slen; i++) {
        switch (lens[s[i]&0xff]) {
        case 1: buf[b->offset++] = s[i];
                break;
        case 2: buf[b->offset++] = '\\';
                switch (s[i]) {
                case '\"': buf[b->offset++] = '"';  break;
                case '\\': buf[b->offset++] = '\\'; break;
                case '\n': buf[b->offset++] = 'n';  break;
                case '\b': buf[b->offset++] = 'b';  break;
                case '\f': buf[b->offset++] = 'f';  break;
                case '\t': buf[b->offset++] = 't';  break;
                case '\r': buf[b->offset++] = 'r';  break;
                }
                break;
        case 6: buf[b->offset++] = '\\';
                buf[b->offset++] = 'u';
                buf[b->offset++] = '0';
                buf[b->offset++] = '0';
                buf[b->offset++] = '0' + (s[i] >> 4);
                buf[b->offset++] = '0' + (s[i] & 15);
                break;
        }
    }
    buf[b->offset++] = '"';
    if (colon) {
        buf[b->offset++] = ':';
    }
    return JSONB_SUCCESS;
}

/* Insert true/false into the buffer. */
static enum jsonb_result
jsonb_push_bool(struct jsonb *b, char *buf, size_t len, int v)
{
    size_t n = v ? 4 : 5;

    switch (b->stack[b->depth]) {
    default: return JSONB_INVALID;
    case  0: if (b->offset+n >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 6;
             break;
    case  2: if (b->offset+n >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 3;
             break;
    case  4: if (b->offset+n >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 5;
             break;
    case  5: if (b->offset+n+1 >= len) return JSONB_BUFFER;
             buf[b->offset++] = ',';
    }

    if (v) {
        memcpy(buf+b->offset, "true", 4);
    } else {
        memcpy(buf+b->offset, "false", 5);
    }
    b->offset += n;
    return JSONB_SUCCESS;
}

/* Insert null into the buffer. */
static enum jsonb_result
jsonb_push_null(struct jsonb *b, char *buf, size_t len)
{
    switch (b->stack[b->depth]) {
    default: return JSONB_INVALID;
    case  0: if (b->offset+4 >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 6;
             break;
    case  2: if (b->offset+4 >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 3;
             break;
    case  4: if (b->offset+4 >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 5;
             break;
    case  5: if (b->offset+5 >= len) return JSONB_BUFFER;
             buf[b->offset++] = ',';
    }

    memcpy(buf+b->offset, "null", 4);
    b->offset += 4;
    return JSONB_SUCCESS;
}

/* Insert a double-precision float into the buffer.
 *
 * The shortest round-trip precision is automatically selected.
 */
static enum jsonb_result
jsonb_push_number(struct jsonb *b, char *buf, size_t len, double v)
{
    int i;
    int bestlen;
    char best[32];

    bestlen = sprintf(best, "%.17g", v);
    for (i = 16; i > 0; i--) {
        char *end, buf[sizeof(best)];
        int len = sprintf(buf, "%.*g", i, v);
        double r = strtod(buf, &end);
        if (*end) {
            return JSONB_INVALID;  /* NaN or infinity */
        } else if (v == r) {
            if (len < bestlen) {
                bestlen = len;
                memcpy(best, buf, sizeof(buf));
            }

        } else {
            break;
        }
    }

    switch (b->stack[b->depth]) {
    default: return JSONB_INVALID;
    case  0: if (b->offset+bestlen >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 6;
             break;
    case  2: if (b->offset+bestlen >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 3;
             break;
    case  4: if (b->offset+bestlen >= len) return JSONB_BUFFER;
             b->stack[b->depth] = 5;
             break;
    case  5: if (b->offset+bestlen+1 >= len) return JSONB_BUFFER;
             buf[b->offset++] = ',';
    }

    memcpy(buf+b->offset, best, bestlen);
    b->offset += bestlen;
    return JSONB_SUCCESS;
}


#ifdef TEST
#include <assert.h>

int
main(void)
{
    int r = 0;
    char buf[256];
    int len = sizeof(buf)-1;
    struct jsonb b[1] = JSONB_INIT;

    r |= jsonb_push_array(b, buf, len); {
        r |= jsonb_push_bool(b, buf, len, 1);
        r |= jsonb_push_bool(b, buf, len, 0);
        r |= jsonb_push_null(b, buf, len);
        r |= jsonb_push_string(b, buf, len, "hello", -1);
        r |= jsonb_push_number(b, buf, len, 3.141592653589793);
        r |= jsonb_push_object(b, buf, len); {
            r |= jsonb_push_string(b, buf, len, "key1", -1);
            r |= jsonb_push_string(b, buf, len, "a\"b", 3);
            r |= jsonb_push_string(b, buf, len, "key2", -1);
            r |= jsonb_push_number(b, buf, len, -1234);
        } r |= jsonb_pop_object(b, buf, len);
    } r |= jsonb_pop_array(b, buf, len);

    assert(!r);
    assert(JSONB_DONE(*b));

    buf[b->offset++] = '\n';
    fwrite(buf, b->offset, 1, stdout);
    return 0;
}
#endif
