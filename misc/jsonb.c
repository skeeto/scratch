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
 * error return. This ensures the inputs are not modified if something
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
jsonb_push_string(struct jsonb *b, char *buf, size_t len, const char *s, size_t slen)
{
    static const unsigned char lens[256] = {
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
        int c = s[i] & 0xff;
        switch (lens[c]) {
        case 1: buf[b->offset++] = c;
                break;
        case 2: buf[b->offset++] = '\\';
                buf[b->offset++] = "..\".....btn.fr..............\\"[c&31];
                break;
        case 6: buf[b->offset++] = '\\';
                buf[b->offset++] = 'u';
                buf[b->offset++] = '0';
                buf[b->offset++] = '0';
                buf[b->offset++] = '0' + (c >> 4);
                buf[b->offset++] = '0' + (c & 15);
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


#ifdef EXAMPLE
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
        r |= jsonb_push_string(b, buf, len, "\x19\b\t\n\f\r\"\\", -1);
        r |= jsonb_push_number(b, buf, len, 3.141592653589793);
        r |= jsonb_push_object(b, buf, len); {
            r |= jsonb_push_string(b, buf, len, "k1", -1);
            r |= jsonb_push_string(b, buf, len, 0, 0);
            r |= jsonb_push_string(b, buf, len, "k2", -1);
            r |= jsonb_push_number(b, buf, len, -123);
        } r |= jsonb_pop_object(b, buf, len);
    } r |= jsonb_pop_array(b, buf, len);

    assert(!r);
    assert(JSONB_DONE(*b));

    buf[b->offset++] = '\n';
    fwrite(buf, b->offset, 1, stdout);
    return 0;
}

#elif FUZZ
/* Usage:
 *   $ mkdir in
 *   $ printf '\x02\x04\x05\x06\x00\x0ahi\x07\x01\x03' >in/example
 *   $ afl-gcc -DFUZZ -m32 -Os -fsanitize=address,undefined jsonb.c
 *   $ afl-fuzz -m800 -i in -o out -- ./a.out
 */

int
main(void)
{
    char buf[1<<15], cmd[1<<12];
    struct jsonb b[1] = JSONB_INIT;
    int i, r = 0, cmdlen, len = sizeof(buf)-1;

    cmdlen = fread(cmd, 1, sizeof(cmd), stdin);
    for (i = 0; !r && i < cmdlen; i++) {
        int c = cmd[i] & 0xff;
        switch (c) {
        case  0: r = jsonb_push_object(b, buf, len);        break;
        case  1: r = jsonb_pop_object(b, buf, len);         break;
        case  2: r = jsonb_push_array(b, buf, len);         break;
        case  3: r = jsonb_pop_array(b, buf, len);          break;
        case  4: r = jsonb_push_bool(b, buf, len, 0);       break;
        case  5: r = jsonb_push_bool(b, buf, len, 1);       break;
        case  6: r = jsonb_push_null(b, buf, len);          break;
        case  7: r = jsonb_push_number(b, buf, len, i/3.0); break;
        default: if (c-8 > cmdlen - i - 1) {
                     r = JSONB_INVALID;
                 } else {
                     r = jsonb_push_string(b, buf, len, cmd+i+1, c-8);
                     i += c - 8;
                 }
        }
    }

    buf[b->offset] = '\n';
    fwrite(buf, b->offset+1, 1, stdout);
    fflush(stdout);
    return !(!ferror(stdin) && !ferror(stdout) && !r && JSONB_DONE(*b));
}

#elif TEST
int
main(void)
{
    static const struct {
        char cmdlen, cmd[6], outlen, out[25];
    } tests[] = {
        {1, {4,0,0,0,0,0}, 5,  "false"},
        {1, {5,0,0,0,0,0}, 4,  "true"},
        {1, {6,0,0,0,0,0}, 4,  "null"},
        {1, {7,0,0,0,0,0}, 1,  "0"},
        {1, {8,0,0,0,0,0}, 2,  "\"\""},
        {2, {0,1,0,0,0,0}, 2,  "{}"},
        {2, {2,3,0,0,0,0}, 2,  "[]"},
        {3, {2,4,3,0,0,0}, 7,  "[false]"},
        {3, {2,5,3,0,0,0}, 6,  "[true]"},
        {3, {2,6,3,0,0,0}, 6,  "[null]"},
        {3, {2,7,3,0,0,0}, 3,  "[1]"},
        {3, {2,8,3,0,0,0}, 4,  "[\"\"]"},
        {4, {0,8,4,1,0,0}, 10, "{\"\":false}"},
        {4, {0,8,5,1,0,0}, 9,  "{\"\":true}"},
        {4, {0,8,6,1,0,0}, 9,  "{\"\":null}"},
        {4, {0,8,7,1,0,0}, 6,  "{\"\":2}"},
        {4, {0,8,8,1,0,0}, 7,  "{\"\":\"\"}"},
        {4, {2,0,1,3,0,0}, 4,  "[{}]"},
        {4, {2,2,3,3,0,0}, 4,  "[[]]"},
        {4, {2,4,4,3,0,0}, 13, "[false,false]"},
        {4, {2,5,4,3,0,0}, 12, "[true,false]"},
        {4, {2,6,4,3,0,0}, 12, "[null,false]"},
        {4, {2,7,4,3,0,0}, 9,  "[1,false]"},
        {4, {2,8,4,3,0,0}, 10, "[\"\",false]"},
        {4, {2,4,5,3,0,0}, 12, "[false,true]"},
        {4, {2,5,5,3,0,0}, 11, "[true,true]"},
        {4, {2,6,5,3,0,0}, 11, "[null,true]"},
        {4, {2,7,5,3,0,0}, 8,  "[1,true]"},
        {4, {2,8,5,3,0,0}, 9,  "[\"\",true]"},
        {4, {2,4,6,3,0,0}, 12, "[false,null]"},
        {4, {2,5,6,3,0,0}, 11, "[true,null]"},
        {4, {2,6,6,3,0,0}, 11, "[null,null]"},
        {4, {2,7,6,3,0,0}, 8,  "[1,null]"},
        {4, {2,8,6,3,0,0}, 9,  "[\"\",null]"},
        {4, {2,4,7,3,0,0}, 9,  "[false,2]"},
        {4, {2,5,7,3,0,0}, 8,  "[true,2]"},
        {4, {2,6,7,3,0,0}, 8,  "[null,2]"},
        {4, {2,7,7,3,0,0}, 5,  "[1,2]"},
        {4, {2,8,7,3,0,0}, 6,  "[\"\",2]"},
        {4, {2,4,8,3,0,0}, 10, "[false,\"\"]"},
        {4, {2,5,8,3,0,0}, 9,  "[true,\"\"]"},
        {4, {2,6,8,3,0,0}, 9,  "[null,\"\"]"},
        {4, {2,7,8,3,0,0}, 6,  "[1,\"\"]"},
        {4, {2,8,8,3,0,0}, 7,  "[\"\",\"\"]"},
        {5, {0,8,0,1,1,0}, 7,  "{\"\":{}}"},
        {5, {0,8,2,3,1,0}, 7,  "{\"\":[]}"},
        {5, {2,4,0,1,3,0}, 10, "[false,{}]"},
        {5, {2,5,0,1,3,0}, 9,  "[true,{}]"},
        {5, {2,6,0,1,3,0}, 9,  "[null,{}]"},
        {5, {2,7,0,1,3,0}, 6,  "[1,{}]"},
        {5, {2,8,0,1,3,0}, 7,  "[\"\",{}]"},
        {5, {2,4,2,3,3,0}, 10, "[false,[]]"},
        {5, {2,5,2,3,3,0}, 9,  "[true,[]]"},
        {5, {2,6,2,3,3,0}, 9,  "[null,[]]"},
        {5, {2,7,2,3,3,0}, 6,  "[1,[]]"},
        {5, {2,8,2,3,3,0}, 7,  "[\"\",[]]"},
        {5, {2,2,4,3,3,0}, 9,  "[[false]]"},
        {5, {2,2,5,3,3,0}, 8,  "[[true]]"},
        {5, {2,2,6,3,3,0}, 8,  "[[null]]"},
        {5, {2,2,7,3,3,0}, 5,  "[[2]]"},
        {5, {2,2,8,3,3,0}, 6,  "[[\"\"]]"},
        {5, {2,0,1,4,3,0}, 10, "[{},false]"},
        {5, {2,2,3,4,3,0}, 10, "[[],false]"},
        {5, {2,4,4,4,3,0}, 19, "[false,false,false]"},
        {5, {2,5,4,4,3,0}, 18, "[true,false,false]"},
        {5, {2,6,4,4,3,0}, 18, "[null,false,false]"},
        {5, {2,7,4,4,3,0}, 15, "[1,false,false]"},
        {5, {2,8,4,4,3,0}, 16, "[\"\",false,false]"},
        {5, {2,4,5,4,3,0}, 18, "[false,true,false]"},
        {5, {2,5,5,4,3,0}, 17, "[true,true,false]"},
        {5, {2,6,5,4,3,0}, 17, "[null,true,false]"},
        {5, {2,7,5,4,3,0}, 14, "[1,true,false]"},
        {5, {2,8,5,4,3,0}, 15, "[\"\",true,false]"},
        {5, {2,4,6,4,3,0}, 18, "[false,null,false]"},
        {5, {2,5,6,4,3,0}, 17, "[true,null,false]"},
        {5, {2,6,6,4,3,0}, 17, "[null,null,false]"},
        {5, {2,7,6,4,3,0}, 14, "[1,null,false]"},
        {5, {2,8,6,4,3,0}, 15, "[\"\",null,false]"},
        {5, {2,4,7,4,3,0}, 15, "[false,2,false]"},
        {5, {2,5,7,4,3,0}, 14, "[true,2,false]"},
        {5, {2,6,7,4,3,0}, 14, "[null,2,false]"},
        {5, {2,7,7,4,3,0}, 11, "[1,2,false]"},
        {5, {2,8,7,4,3,0}, 12, "[\"\",2,false]"},
        {5, {2,4,8,4,3,0}, 16, "[false,\"\",false]"},
        {5, {2,5,8,4,3,0}, 15, "[true,\"\",false]"},
        {5, {2,6,8,4,3,0}, 15, "[null,\"\",false]"},
        {5, {2,7,8,4,3,0}, 12, "[1,\"\",false]"},
        {5, {2,8,8,4,3,0}, 13, "[\"\",\"\",false]"},
        {5, {2,0,1,5,3,0}, 9,  "[{},true]"},
        {5, {2,2,3,5,3,0}, 9,  "[[],true]"},
        {5, {2,4,4,5,3,0}, 18, "[false,false,true]"},
        {5, {2,5,4,5,3,0}, 17, "[true,false,true]"},
        {5, {2,6,4,5,3,0}, 17, "[null,false,true]"},
        {5, {2,7,4,5,3,0}, 14, "[1,false,true]"},
        {5, {2,8,4,5,3,0}, 15, "[\"\",false,true]"},
        {5, {2,4,5,5,3,0}, 17, "[false,true,true]"},
        {5, {2,5,5,5,3,0}, 16, "[true,true,true]"},
        {5, {2,6,5,5,3,0}, 16, "[null,true,true]"},
        {5, {2,7,5,5,3,0}, 13, "[1,true,true]"},
        {5, {2,8,5,5,3,0}, 14, "[\"\",true,true]"},
        {5, {2,4,6,5,3,0}, 17, "[false,null,true]"},
        {5, {2,5,6,5,3,0}, 16, "[true,null,true]"},
        {5, {2,6,6,5,3,0}, 16, "[null,null,true]"},
        {5, {2,7,6,5,3,0}, 13, "[1,null,true]"},
        {5, {2,8,6,5,3,0}, 14, "[\"\",null,true]"},
        {5, {2,4,7,5,3,0}, 14, "[false,2,true]"},
        {5, {2,5,7,5,3,0}, 13, "[true,2,true]"},
        {5, {2,6,7,5,3,0}, 13, "[null,2,true]"},
        {5, {2,7,7,5,3,0}, 10, "[1,2,true]"},
        {5, {2,8,7,5,3,0}, 11, "[\"\",2,true]"},
        {5, {2,4,8,5,3,0}, 15, "[false,\"\",true]"},
        {5, {2,5,8,5,3,0}, 14, "[true,\"\",true]"},
        {5, {2,6,8,5,3,0}, 14, "[null,\"\",true]"},
        {5, {2,7,8,5,3,0}, 11, "[1,\"\",true]"},
        {5, {2,8,8,5,3,0}, 12, "[\"\",\"\",true]"},
        {5, {2,0,1,6,3,0}, 9,  "[{},null]"},
        {5, {2,2,3,6,3,0}, 9,  "[[],null]"},
        {5, {2,4,4,6,3,0}, 18, "[false,false,null]"},
        {5, {2,5,4,6,3,0}, 17, "[true,false,null]"},
        {5, {2,6,4,6,3,0}, 17, "[null,false,null]"},
        {5, {2,7,4,6,3,0}, 14, "[1,false,null]"},
        {5, {2,8,4,6,3,0}, 15, "[\"\",false,null]"},
        {5, {2,4,5,6,3,0}, 17, "[false,true,null]"},
        {5, {2,5,5,6,3,0}, 16, "[true,true,null]"},
        {5, {2,6,5,6,3,0}, 16, "[null,true,null]"},
        {5, {2,7,5,6,3,0}, 13, "[1,true,null]"},
        {5, {2,8,5,6,3,0}, 14, "[\"\",true,null]"},
        {5, {2,4,6,6,3,0}, 17, "[false,null,null]"},
        {5, {2,5,6,6,3,0}, 16, "[true,null,null]"},
        {5, {2,6,6,6,3,0}, 16, "[null,null,null]"},
        {5, {2,7,6,6,3,0}, 13, "[1,null,null]"},
        {5, {2,8,6,6,3,0}, 14, "[\"\",null,null]"},
        {5, {2,4,7,6,3,0}, 14, "[false,2,null]"},
        {5, {2,5,7,6,3,0}, 13, "[true,2,null]"},
        {5, {2,6,7,6,3,0}, 13, "[null,2,null]"},
        {5, {2,7,7,6,3,0}, 10, "[1,2,null]"},
        {5, {2,8,7,6,3,0}, 11, "[\"\",2,null]"},
        {5, {2,4,8,6,3,0}, 15, "[false,\"\",null]"},
        {5, {2,5,8,6,3,0}, 14, "[true,\"\",null]"},
        {5, {2,6,8,6,3,0}, 14, "[null,\"\",null]"},
        {5, {2,7,8,6,3,0}, 11, "[1,\"\",null]"},
        {5, {2,8,8,6,3,0}, 12, "[\"\",\"\",null]"},
        {5, {2,0,1,7,3,0}, 6,  "[{},3]"},
        {5, {2,2,3,7,3,0}, 6,  "[[],3]"},
        {5, {2,4,4,7,3,0}, 15, "[false,false,3]"},
        {5, {2,5,4,7,3,0}, 14, "[true,false,3]"},
        {5, {2,6,4,7,3,0}, 14, "[null,false,3]"},
        {5, {2,7,4,7,3,0}, 11, "[1,false,3]"},
        {5, {2,8,4,7,3,0}, 12, "[\"\",false,3]"},
        {5, {2,4,5,7,3,0}, 14, "[false,true,3]"},
        {5, {2,5,5,7,3,0}, 13, "[true,true,3]"},
        {5, {2,6,5,7,3,0}, 13, "[null,true,3]"},
        {5, {2,7,5,7,3,0}, 10, "[1,true,3]"},
        {5, {2,8,5,7,3,0}, 11, "[\"\",true,3]"},
        {5, {2,4,6,7,3,0}, 14, "[false,null,3]"},
        {5, {2,5,6,7,3,0}, 13, "[true,null,3]"},
        {5, {2,6,6,7,3,0}, 13, "[null,null,3]"},
        {5, {2,7,6,7,3,0}, 10, "[1,null,3]"},
        {5, {2,8,6,7,3,0}, 11, "[\"\",null,3]"},
        {5, {2,4,7,7,3,0}, 11, "[false,2,3]"},
        {5, {2,5,7,7,3,0}, 10, "[true,2,3]"},
        {5, {2,6,7,7,3,0}, 10, "[null,2,3]"},
        {5, {2,7,7,7,3,0}, 7,  "[1,2,3]"},
        {5, {2,8,7,7,3,0}, 8,  "[\"\",2,3]"},
        {5, {2,4,8,7,3,0}, 12, "[false,\"\",3]"},
        {5, {2,5,8,7,3,0}, 11, "[true,\"\",3]"},
        {5, {2,6,8,7,3,0}, 11, "[null,\"\",3]"},
        {5, {2,7,8,7,3,0}, 8,  "[1,\"\",3]"},
        {5, {2,8,8,7,3,0}, 9,  "[\"\",\"\",3]"},
        {5, {2,0,1,8,3,0}, 7,  "[{},\"\"]"},
        {5, {2,2,3,8,3,0}, 7,  "[[],\"\"]"},
        {5, {2,4,4,8,3,0}, 16, "[false,false,\"\"]"},
        {5, {2,5,4,8,3,0}, 15, "[true,false,\"\"]"},
        {5, {2,6,4,8,3,0}, 15, "[null,false,\"\"]"},
        {5, {2,7,4,8,3,0}, 12, "[1,false,\"\"]"},
        {5, {2,8,4,8,3,0}, 13, "[\"\",false,\"\"]"},
        {5, {2,4,5,8,3,0}, 15, "[false,true,\"\"]"},
        {5, {2,5,5,8,3,0}, 14, "[true,true,\"\"]"},
        {5, {2,6,5,8,3,0}, 14, "[null,true,\"\"]"},
        {5, {2,7,5,8,3,0}, 11, "[1,true,\"\"]"},
        {5, {2,8,5,8,3,0}, 12, "[\"\",true,\"\"]"},
        {5, {2,4,6,8,3,0}, 15, "[false,null,\"\"]"},
        {5, {2,5,6,8,3,0}, 14, "[true,null,\"\"]"},
        {5, {2,6,6,8,3,0}, 14, "[null,null,\"\"]"},
        {5, {2,7,6,8,3,0}, 11, "[1,null,\"\"]"},
        {5, {2,8,6,8,3,0}, 12, "[\"\",null,\"\"]"},
        {5, {2,4,7,8,3,0}, 12, "[false,2,\"\"]"},
        {5, {2,5,7,8,3,0}, 11, "[true,2,\"\"]"},
        {5, {2,6,7,8,3,0}, 11, "[null,2,\"\"]"},
        {5, {2,7,7,8,3,0}, 8,  "[1,2,\"\"]"},
        {5, {2,8,7,8,3,0}, 9,  "[\"\",2,\"\"]"},
        {5, {2,4,8,8,3,0}, 13, "[false,\"\",\"\"]"},
        {5, {2,5,8,8,3,0}, 12, "[true,\"\",\"\"]"},
        {5, {2,6,8,8,3,0}, 12, "[null,\"\",\"\"]"},
        {5, {2,7,8,8,3,0}, 9,  "[1,\"\",\"\"]"},
        {5, {2,8,8,8,3,0}, 10, "[\"\",\"\",\"\"]"},
        {6, {0,8,2,4,3,1}, 12, "{\"\":[false]}"},
        {6, {0,8,2,5,3,1}, 11, "{\"\":[true]}"},
        {6, {0,8,2,6,3,1}, 11, "{\"\":[null]}"},
        {6, {0,8,2,7,3,1}, 8,  "{\"\":[3]}"},
        {6, {0,8,2,8,3,1}, 9,  "{\"\":[\"\"]}"},
        {6, {0,8,4,8,4,1}, 19, "{\"\":false,\"\":false}"},
        {6, {0,8,5,8,4,1}, 18, "{\"\":true,\"\":false}"},
        {6, {0,8,6,8,4,1}, 18, "{\"\":null,\"\":false}"},
        {6, {0,8,7,8,4,1}, 15, "{\"\":2,\"\":false}"},
        {6, {0,8,8,8,4,1}, 16, "{\"\":\"\",\"\":false}"},
        {6, {0,8,4,8,5,1}, 18, "{\"\":false,\"\":true}"},
        {6, {0,8,5,8,5,1}, 17, "{\"\":true,\"\":true}"},
        {6, {0,8,6,8,5,1}, 17, "{\"\":null,\"\":true}"},
        {6, {0,8,7,8,5,1}, 14, "{\"\":2,\"\":true}"},
        {6, {0,8,8,8,5,1}, 15, "{\"\":\"\",\"\":true}"},
        {6, {0,8,4,8,6,1}, 18, "{\"\":false,\"\":null}"},
        {6, {0,8,5,8,6,1}, 17, "{\"\":true,\"\":null}"},
        {6, {0,8,6,8,6,1}, 17, "{\"\":null,\"\":null}"},
        {6, {0,8,7,8,6,1}, 14, "{\"\":2,\"\":null}"},
        {6, {0,8,8,8,6,1}, 15, "{\"\":\"\",\"\":null}"},
        {6, {0,8,4,8,7,1}, 15, "{\"\":false,\"\":4}"},
        {6, {0,8,5,8,7,1}, 14, "{\"\":true,\"\":4}"},
        {6, {0,8,6,8,7,1}, 14, "{\"\":null,\"\":4}"},
        {6, {0,8,7,8,7,1}, 11, "{\"\":2,\"\":4}"},
        {6, {0,8,8,8,7,1}, 12, "{\"\":\"\",\"\":4}"},
        {6, {0,8,4,8,8,1}, 16, "{\"\":false,\"\":\"\"}"},
        {6, {0,8,5,8,8,1}, 15, "{\"\":true,\"\":\"\"}"},
        {6, {0,8,6,8,8,1}, 15, "{\"\":null,\"\":\"\"}"},
        {6, {0,8,7,8,8,1}, 12, "{\"\":2,\"\":\"\"}"},
        {6, {0,8,8,8,8,1}, 13, "{\"\":\"\",\"\":\"\"}"},
        {6, {2,0,1,0,1,3}, 7,  "[{},{}]"},
        {6, {2,2,3,0,1,3}, 7,  "[[],{}]"},
        {6, {2,4,4,0,1,3}, 16, "[false,false,{}]"},
        {6, {2,5,4,0,1,3}, 15, "[true,false,{}]"},
        {6, {2,6,4,0,1,3}, 15, "[null,false,{}]"},
        {6, {2,7,4,0,1,3}, 12, "[1,false,{}]"},
        {6, {2,8,4,0,1,3}, 13, "[\"\",false,{}]"},
        {6, {2,4,5,0,1,3}, 15, "[false,true,{}]"},
        {6, {2,5,5,0,1,3}, 14, "[true,true,{}]"},
        {6, {2,6,5,0,1,3}, 14, "[null,true,{}]"},
        {6, {2,7,5,0,1,3}, 11, "[1,true,{}]"},
        {6, {2,8,5,0,1,3}, 12, "[\"\",true,{}]"},
        {6, {2,4,6,0,1,3}, 15, "[false,null,{}]"},
        {6, {2,5,6,0,1,3}, 14, "[true,null,{}]"},
        {6, {2,6,6,0,1,3}, 14, "[null,null,{}]"},
        {6, {2,7,6,0,1,3}, 11, "[1,null,{}]"},
        {6, {2,8,6,0,1,3}, 12, "[\"\",null,{}]"},
        {6, {2,4,7,0,1,3}, 12, "[false,2,{}]"},
        {6, {2,5,7,0,1,3}, 11, "[true,2,{}]"},
        {6, {2,6,7,0,1,3}, 11, "[null,2,{}]"},
        {6, {2,7,7,0,1,3}, 8,  "[1,2,{}]"},
        {6, {2,8,7,0,1,3}, 9,  "[\"\",2,{}]"},
        {6, {2,4,8,0,1,3}, 13, "[false,\"\",{}]"},
        {6, {2,5,8,0,1,3}, 12, "[true,\"\",{}]"},
        {6, {2,6,8,0,1,3}, 12, "[null,\"\",{}]"},
        {6, {2,7,8,0,1,3}, 9,  "[1,\"\",{}]"},
        {6, {2,8,8,0,1,3}, 10, "[\"\",\"\",{}]"},
        {6, {2,0,8,4,1,3}, 12, "[{\"\":false}]"},
        {6, {2,0,8,5,1,3}, 11, "[{\"\":true}]"},
        {6, {2,0,8,6,1,3}, 11, "[{\"\":null}]"},
        {6, {2,0,8,7,1,3}, 8,  "[{\"\":3}]"},
        {6, {2,0,8,8,1,3}, 9,  "[{\"\":\"\"}]"},
        {6, {2,2,0,1,3,3}, 6,  "[[{}]]"},
        {6, {2,0,1,2,3,3}, 7,  "[{},[]]"},
        {6, {2,2,3,2,3,3}, 7,  "[[],[]]"},
        {6, {2,4,4,2,3,3}, 16, "[false,false,[]]"},
        {6, {2,5,4,2,3,3}, 15, "[true,false,[]]"},
        {6, {2,6,4,2,3,3}, 15, "[null,false,[]]"},
        {6, {2,7,4,2,3,3}, 12, "[1,false,[]]"},
        {6, {2,8,4,2,3,3}, 13, "[\"\",false,[]]"},
        {6, {2,4,5,2,3,3}, 15, "[false,true,[]]"},
        {6, {2,5,5,2,3,3}, 14, "[true,true,[]]"},
        {6, {2,6,5,2,3,3}, 14, "[null,true,[]]"},
        {6, {2,7,5,2,3,3}, 11, "[1,true,[]]"},
        {6, {2,8,5,2,3,3}, 12, "[\"\",true,[]]"},
        {6, {2,4,6,2,3,3}, 15, "[false,null,[]]"},
        {6, {2,5,6,2,3,3}, 14, "[true,null,[]]"},
        {6, {2,6,6,2,3,3}, 14, "[null,null,[]]"},
        {6, {2,7,6,2,3,3}, 11, "[1,null,[]]"},
        {6, {2,8,6,2,3,3}, 12, "[\"\",null,[]]"},
        {6, {2,4,7,2,3,3}, 12, "[false,2,[]]"},
        {6, {2,5,7,2,3,3}, 11, "[true,2,[]]"},
        {6, {2,6,7,2,3,3}, 11, "[null,2,[]]"},
        {6, {2,7,7,2,3,3}, 8,  "[1,2,[]]"},
        {6, {2,8,7,2,3,3}, 9,  "[\"\",2,[]]"},
        {6, {2,4,8,2,3,3}, 13, "[false,\"\",[]]"},
        {6, {2,5,8,2,3,3}, 12, "[true,\"\",[]]"},
        {6, {2,6,8,2,3,3}, 12, "[null,\"\",[]]"},
        {6, {2,7,8,2,3,3}, 9,  "[1,\"\",[]]"},
        {6, {2,8,8,2,3,3}, 10, "[\"\",\"\",[]]"},
        {6, {2,2,2,3,3,3}, 6,  "[[[]]]"},
        {6, {2,4,2,4,3,3}, 15, "[false,[false]]"},
        {6, {2,5,2,4,3,3}, 14, "[true,[false]]"},
        {6, {2,6,2,4,3,3}, 14, "[null,[false]]"},
        {6, {2,7,2,4,3,3}, 11, "[1,[false]]"},
        {6, {2,8,2,4,3,3}, 12, "[\"\",[false]]"},
        {6, {2,2,4,4,3,3}, 15, "[[false,false]]"},
        {6, {2,2,5,4,3,3}, 14, "[[true,false]]"},
        {6, {2,2,6,4,3,3}, 14, "[[null,false]]"},
        {6, {2,2,7,4,3,3}, 11, "[[2,false]]"},
        {6, {2,2,8,4,3,3}, 12, "[[\"\",false]]"},
        {6, {2,4,2,5,3,3}, 14, "[false,[true]]"},
        {6, {2,5,2,5,3,3}, 13, "[true,[true]]"},
        {6, {2,6,2,5,3,3}, 13, "[null,[true]]"},
        {6, {2,7,2,5,3,3}, 10, "[1,[true]]"},
        {6, {2,8,2,5,3,3}, 11, "[\"\",[true]]"},
        {6, {2,2,4,5,3,3}, 14, "[[false,true]]"},
        {6, {2,2,5,5,3,3}, 13, "[[true,true]]"},
        {6, {2,2,6,5,3,3}, 13, "[[null,true]]"},
        {6, {2,2,7,5,3,3}, 10, "[[2,true]]"},
        {6, {2,2,8,5,3,3}, 11, "[[\"\",true]]"},
        {6, {2,4,2,6,3,3}, 14, "[false,[null]]"},
        {6, {2,5,2,6,3,3}, 13, "[true,[null]]"},
        {6, {2,6,2,6,3,3}, 13, "[null,[null]]"},
        {6, {2,7,2,6,3,3}, 10, "[1,[null]]"},
        {6, {2,8,2,6,3,3}, 11, "[\"\",[null]]"},
        {6, {2,2,4,6,3,3}, 14, "[[false,null]]"},
        {6, {2,2,5,6,3,3}, 13, "[[true,null]]"},
        {6, {2,2,6,6,3,3}, 13, "[[null,null]]"},
        {6, {2,2,7,6,3,3}, 10, "[[2,null]]"},
        {6, {2,2,8,6,3,3}, 11, "[[\"\",null]]"},
        {6, {2,4,2,7,3,3}, 11, "[false,[3]]"},
        {6, {2,5,2,7,3,3}, 10, "[true,[3]]"},
        {6, {2,6,2,7,3,3}, 10, "[null,[3]]"},
        {6, {2,7,2,7,3,3}, 7,  "[1,[3]]"},
        {6, {2,8,2,7,3,3}, 8,  "[\"\",[3]]"},
        {6, {2,2,4,7,3,3}, 11, "[[false,3]]"},
        {6, {2,2,5,7,3,3}, 10, "[[true,3]]"},
        {6, {2,2,6,7,3,3}, 10, "[[null,3]]"},
        {6, {2,2,7,7,3,3}, 7,  "[[2,3]]"},
        {6, {2,2,8,7,3,3}, 8,  "[[\"\",3]]"},
        {6, {2,4,2,8,3,3}, 12, "[false,[\"\"]]"},
        {6, {2,5,2,8,3,3}, 11, "[true,[\"\"]]"},
        {6, {2,6,2,8,3,3}, 11, "[null,[\"\"]]"},
        {6, {2,7,2,8,3,3}, 8,  "[1,[\"\"]]"},
        {6, {2,8,2,8,3,3}, 9,  "[\"\",[\"\"]]"},
        {6, {2,2,4,8,3,3}, 12, "[[false,\"\"]]"},
        {6, {2,2,5,8,3,3}, 11, "[[true,\"\"]]"},
        {6, {2,2,6,8,3,3}, 11, "[[null,\"\"]]"},
        {6, {2,2,7,8,3,3}, 8,  "[[2,\"\"]]"},
        {6, {2,2,8,8,3,3}, 9,  "[[\"\",\"\"]]"},
        {6, {2,4,0,1,4,3}, 16, "[false,{},false]"},
        {6, {2,5,0,1,4,3}, 15, "[true,{},false]"},
        {6, {2,6,0,1,4,3}, 15, "[null,{},false]"},
        {6, {2,7,0,1,4,3}, 12, "[1,{},false]"},
        {6, {2,8,0,1,4,3}, 13, "[\"\",{},false]"},
        {6, {2,4,2,3,4,3}, 16, "[false,[],false]"},
        {6, {2,5,2,3,4,3}, 15, "[true,[],false]"},
        {6, {2,6,2,3,4,3}, 15, "[null,[],false]"},
        {6, {2,7,2,3,4,3}, 12, "[1,[],false]"},
        {6, {2,8,2,3,4,3}, 13, "[\"\",[],false]"},
        {6, {2,2,4,3,4,3}, 15, "[[false],false]"},
        {6, {2,2,5,3,4,3}, 14, "[[true],false]"},
        {6, {2,2,6,3,4,3}, 14, "[[null],false]"},
        {6, {2,2,7,3,4,3}, 11, "[[2],false]"},
        {6, {2,2,8,3,4,3}, 12, "[[\"\"],false]"},
        {6, {2,0,1,4,4,3}, 16, "[{},false,false]"},
        {6, {2,2,3,4,4,3}, 16, "[[],false,false]"},
        {6, {2,4,4,4,4,3}, 25, "[false,false,false,false]"},
        {6, {2,5,4,4,4,3}, 24, "[true,false,false,false]"},
        {6, {2,6,4,4,4,3}, 24, "[null,false,false,false]"},
        {6, {2,7,4,4,4,3}, 21, "[1,false,false,false]"},
        {6, {2,8,4,4,4,3}, 22, "[\"\",false,false,false]"},
        {6, {2,4,5,4,4,3}, 24, "[false,true,false,false]"},
        {6, {2,5,5,4,4,3}, 23, "[true,true,false,false]"},
        {6, {2,6,5,4,4,3}, 23, "[null,true,false,false]"},
        {6, {2,7,5,4,4,3}, 20, "[1,true,false,false]"},
        {6, {2,8,5,4,4,3}, 21, "[\"\",true,false,false]"},
        {6, {2,4,6,4,4,3}, 24, "[false,null,false,false]"},
        {6, {2,5,6,4,4,3}, 23, "[true,null,false,false]"},
        {6, {2,6,6,4,4,3}, 23, "[null,null,false,false]"},
        {6, {2,7,6,4,4,3}, 20, "[1,null,false,false]"},
        {6, {2,8,6,4,4,3}, 21, "[\"\",null,false,false]"},
        {6, {2,4,7,4,4,3}, 21, "[false,2,false,false]"},
        {6, {2,5,7,4,4,3}, 20, "[true,2,false,false]"},
        {6, {2,6,7,4,4,3}, 20, "[null,2,false,false]"},
        {6, {2,7,7,4,4,3}, 17, "[1,2,false,false]"},
        {6, {2,8,7,4,4,3}, 18, "[\"\",2,false,false]"},
        {6, {2,4,8,4,4,3}, 22, "[false,\"\",false,false]"},
        {6, {2,5,8,4,4,3}, 21, "[true,\"\",false,false]"},
        {6, {2,6,8,4,4,3}, 21, "[null,\"\",false,false]"},
        {6, {2,7,8,4,4,3}, 18, "[1,\"\",false,false]"},
        {6, {2,8,8,4,4,3}, 19, "[\"\",\"\",false,false]"},
        {6, {2,0,1,5,4,3}, 15, "[{},true,false]"},
        {6, {2,2,3,5,4,3}, 15, "[[],true,false]"},
        {6, {2,4,4,5,4,3}, 24, "[false,false,true,false]"},
        {6, {2,5,4,5,4,3}, 23, "[true,false,true,false]"},
        {6, {2,6,4,5,4,3}, 23, "[null,false,true,false]"},
        {6, {2,7,4,5,4,3}, 20, "[1,false,true,false]"},
        {6, {2,8,4,5,4,3}, 21, "[\"\",false,true,false]"},
        {6, {2,4,5,5,4,3}, 23, "[false,true,true,false]"},
        {6, {2,5,5,5,4,3}, 22, "[true,true,true,false]"},
        {6, {2,6,5,5,4,3}, 22, "[null,true,true,false]"},
        {6, {2,7,5,5,4,3}, 19, "[1,true,true,false]"},
        {6, {2,8,5,5,4,3}, 20, "[\"\",true,true,false]"},
        {6, {2,4,6,5,4,3}, 23, "[false,null,true,false]"},
        {6, {2,5,6,5,4,3}, 22, "[true,null,true,false]"},
        {6, {2,6,6,5,4,3}, 22, "[null,null,true,false]"},
        {6, {2,7,6,5,4,3}, 19, "[1,null,true,false]"},
        {6, {2,8,6,5,4,3}, 20, "[\"\",null,true,false]"},
        {6, {2,4,7,5,4,3}, 20, "[false,2,true,false]"},
        {6, {2,5,7,5,4,3}, 19, "[true,2,true,false]"},
        {6, {2,6,7,5,4,3}, 19, "[null,2,true,false]"},
        {6, {2,7,7,5,4,3}, 16, "[1,2,true,false]"},
        {6, {2,8,7,5,4,3}, 17, "[\"\",2,true,false]"},
        {6, {2,4,8,5,4,3}, 21, "[false,\"\",true,false]"},
        {6, {2,5,8,5,4,3}, 20, "[true,\"\",true,false]"},
        {6, {2,6,8,5,4,3}, 20, "[null,\"\",true,false]"},
        {6, {2,7,8,5,4,3}, 17, "[1,\"\",true,false]"},
        {6, {2,8,8,5,4,3}, 18, "[\"\",\"\",true,false]"},
        {6, {2,0,1,6,4,3}, 15, "[{},null,false]"},
        {6, {2,2,3,6,4,3}, 15, "[[],null,false]"},
        {6, {2,4,4,6,4,3}, 24, "[false,false,null,false]"},
        {6, {2,5,4,6,4,3}, 23, "[true,false,null,false]"},
        {6, {2,6,4,6,4,3}, 23, "[null,false,null,false]"},
        {6, {2,7,4,6,4,3}, 20, "[1,false,null,false]"},
        {6, {2,8,4,6,4,3}, 21, "[\"\",false,null,false]"},
        {6, {2,4,5,6,4,3}, 23, "[false,true,null,false]"},
        {6, {2,5,5,6,4,3}, 22, "[true,true,null,false]"},
        {6, {2,6,5,6,4,3}, 22, "[null,true,null,false]"},
        {6, {2,7,5,6,4,3}, 19, "[1,true,null,false]"},
        {6, {2,8,5,6,4,3}, 20, "[\"\",true,null,false]"},
        {6, {2,4,6,6,4,3}, 23, "[false,null,null,false]"},
        {6, {2,5,6,6,4,3}, 22, "[true,null,null,false]"},
        {6, {2,6,6,6,4,3}, 22, "[null,null,null,false]"},
        {6, {2,7,6,6,4,3}, 19, "[1,null,null,false]"},
        {6, {2,8,6,6,4,3}, 20, "[\"\",null,null,false]"},
        {6, {2,4,7,6,4,3}, 20, "[false,2,null,false]"},
        {6, {2,5,7,6,4,3}, 19, "[true,2,null,false]"},
        {6, {2,6,7,6,4,3}, 19, "[null,2,null,false]"},
        {6, {2,7,7,6,4,3}, 16, "[1,2,null,false]"},
        {6, {2,8,7,6,4,3}, 17, "[\"\",2,null,false]"},
        {6, {2,4,8,6,4,3}, 21, "[false,\"\",null,false]"},
        {6, {2,5,8,6,4,3}, 20, "[true,\"\",null,false]"},
        {6, {2,6,8,6,4,3}, 20, "[null,\"\",null,false]"},
        {6, {2,7,8,6,4,3}, 17, "[1,\"\",null,false]"},
        {6, {2,8,8,6,4,3}, 18, "[\"\",\"\",null,false]"},
        {6, {2,0,1,7,4,3}, 12, "[{},3,false]"},
        {6, {2,2,3,7,4,3}, 12, "[[],3,false]"},
        {6, {2,4,4,7,4,3}, 21, "[false,false,3,false]"},
        {6, {2,5,4,7,4,3}, 20, "[true,false,3,false]"},
        {6, {2,6,4,7,4,3}, 20, "[null,false,3,false]"},
        {6, {2,7,4,7,4,3}, 17, "[1,false,3,false]"},
        {6, {2,8,4,7,4,3}, 18, "[\"\",false,3,false]"},
        {6, {2,4,5,7,4,3}, 20, "[false,true,3,false]"},
        {6, {2,5,5,7,4,3}, 19, "[true,true,3,false]"},
        {6, {2,6,5,7,4,3}, 19, "[null,true,3,false]"},
        {6, {2,7,5,7,4,3}, 16, "[1,true,3,false]"},
        {6, {2,8,5,7,4,3}, 17, "[\"\",true,3,false]"},
        {6, {2,4,6,7,4,3}, 20, "[false,null,3,false]"},
        {6, {2,5,6,7,4,3}, 19, "[true,null,3,false]"},
        {6, {2,6,6,7,4,3}, 19, "[null,null,3,false]"},
        {6, {2,7,6,7,4,3}, 16, "[1,null,3,false]"},
        {6, {2,8,6,7,4,3}, 17, "[\"\",null,3,false]"},
        {6, {2,4,7,7,4,3}, 17, "[false,2,3,false]"},
        {6, {2,5,7,7,4,3}, 16, "[true,2,3,false]"},
        {6, {2,6,7,7,4,3}, 16, "[null,2,3,false]"},
        {6, {2,7,7,7,4,3}, 13, "[1,2,3,false]"},
        {6, {2,8,7,7,4,3}, 14, "[\"\",2,3,false]"},
        {6, {2,4,8,7,4,3}, 18, "[false,\"\",3,false]"},
        {6, {2,5,8,7,4,3}, 17, "[true,\"\",3,false]"},
        {6, {2,6,8,7,4,3}, 17, "[null,\"\",3,false]"},
        {6, {2,7,8,7,4,3}, 14, "[1,\"\",3,false]"},
        {6, {2,8,8,7,4,3}, 15, "[\"\",\"\",3,false]"},
        {6, {2,0,1,8,4,3}, 13, "[{},\"\",false]"},
        {6, {2,2,3,8,4,3}, 13, "[[],\"\",false]"},
        {6, {2,4,4,8,4,3}, 22, "[false,false,\"\",false]"},
        {6, {2,5,4,8,4,3}, 21, "[true,false,\"\",false]"},
        {6, {2,6,4,8,4,3}, 21, "[null,false,\"\",false]"},
        {6, {2,7,4,8,4,3}, 18, "[1,false,\"\",false]"},
        {6, {2,8,4,8,4,3}, 19, "[\"\",false,\"\",false]"},
        {6, {2,4,5,8,4,3}, 21, "[false,true,\"\",false]"},
        {6, {2,5,5,8,4,3}, 20, "[true,true,\"\",false]"},
        {6, {2,6,5,8,4,3}, 20, "[null,true,\"\",false]"},
        {6, {2,7,5,8,4,3}, 17, "[1,true,\"\",false]"},
        {6, {2,8,5,8,4,3}, 18, "[\"\",true,\"\",false]"},
        {6, {2,4,6,8,4,3}, 21, "[false,null,\"\",false]"},
        {6, {2,5,6,8,4,3}, 20, "[true,null,\"\",false]"},
        {6, {2,6,6,8,4,3}, 20, "[null,null,\"\",false]"},
        {6, {2,7,6,8,4,3}, 17, "[1,null,\"\",false]"},
        {6, {2,8,6,8,4,3}, 18, "[\"\",null,\"\",false]"},
        {6, {2,4,7,8,4,3}, 18, "[false,2,\"\",false]"},
        {6, {2,5,7,8,4,3}, 17, "[true,2,\"\",false]"},
        {6, {2,6,7,8,4,3}, 17, "[null,2,\"\",false]"},
        {6, {2,7,7,8,4,3}, 14, "[1,2,\"\",false]"},
        {6, {2,8,7,8,4,3}, 15, "[\"\",2,\"\",false]"},
        {6, {2,4,8,8,4,3}, 19, "[false,\"\",\"\",false]"},
        {6, {2,5,8,8,4,3}, 18, "[true,\"\",\"\",false]"},
        {6, {2,6,8,8,4,3}, 18, "[null,\"\",\"\",false]"},
        {6, {2,7,8,8,4,3}, 15, "[1,\"\",\"\",false]"},
        {6, {2,8,8,8,4,3}, 16, "[\"\",\"\",\"\",false]"},
        {6, {2,4,0,1,5,3}, 15, "[false,{},true]"},
        {6, {2,5,0,1,5,3}, 14, "[true,{},true]"},
        {6, {2,6,0,1,5,3}, 14, "[null,{},true]"},
        {6, {2,7,0,1,5,3}, 11, "[1,{},true]"},
        {6, {2,8,0,1,5,3}, 12, "[\"\",{},true]"},
        {6, {2,4,2,3,5,3}, 15, "[false,[],true]"},
        {6, {2,5,2,3,5,3}, 14, "[true,[],true]"},
        {6, {2,6,2,3,5,3}, 14, "[null,[],true]"},
        {6, {2,7,2,3,5,3}, 11, "[1,[],true]"},
        {6, {2,8,2,3,5,3}, 12, "[\"\",[],true]"},
        {6, {2,2,4,3,5,3}, 14, "[[false],true]"},
        {6, {2,2,5,3,5,3}, 13, "[[true],true]"},
        {6, {2,2,6,3,5,3}, 13, "[[null],true]"},
        {6, {2,2,7,3,5,3}, 10, "[[2],true]"},
        {6, {2,2,8,3,5,3}, 11, "[[\"\"],true]"},
        {6, {2,0,1,4,5,3}, 15, "[{},false,true]"},
        {6, {2,2,3,4,5,3}, 15, "[[],false,true]"},
        {6, {2,4,4,4,5,3}, 24, "[false,false,false,true]"},
        {6, {2,5,4,4,5,3}, 23, "[true,false,false,true]"},
        {6, {2,6,4,4,5,3}, 23, "[null,false,false,true]"},
        {6, {2,7,4,4,5,3}, 20, "[1,false,false,true]"},
        {6, {2,8,4,4,5,3}, 21, "[\"\",false,false,true]"},
        {6, {2,4,5,4,5,3}, 23, "[false,true,false,true]"},
        {6, {2,5,5,4,5,3}, 22, "[true,true,false,true]"},
        {6, {2,6,5,4,5,3}, 22, "[null,true,false,true]"},
        {6, {2,7,5,4,5,3}, 19, "[1,true,false,true]"},
        {6, {2,8,5,4,5,3}, 20, "[\"\",true,false,true]"},
        {6, {2,4,6,4,5,3}, 23, "[false,null,false,true]"},
        {6, {2,5,6,4,5,3}, 22, "[true,null,false,true]"},
        {6, {2,6,6,4,5,3}, 22, "[null,null,false,true]"},
        {6, {2,7,6,4,5,3}, 19, "[1,null,false,true]"},
        {6, {2,8,6,4,5,3}, 20, "[\"\",null,false,true]"},
        {6, {2,4,7,4,5,3}, 20, "[false,2,false,true]"},
        {6, {2,5,7,4,5,3}, 19, "[true,2,false,true]"},
        {6, {2,6,7,4,5,3}, 19, "[null,2,false,true]"},
        {6, {2,7,7,4,5,3}, 16, "[1,2,false,true]"},
        {6, {2,8,7,4,5,3}, 17, "[\"\",2,false,true]"},
        {6, {2,4,8,4,5,3}, 21, "[false,\"\",false,true]"},
        {6, {2,5,8,4,5,3}, 20, "[true,\"\",false,true]"},
        {6, {2,6,8,4,5,3}, 20, "[null,\"\",false,true]"},
        {6, {2,7,8,4,5,3}, 17, "[1,\"\",false,true]"},
        {6, {2,8,8,4,5,3}, 18, "[\"\",\"\",false,true]"},
        {6, {2,0,1,5,5,3}, 14, "[{},true,true]"},
        {6, {2,2,3,5,5,3}, 14, "[[],true,true]"},
        {6, {2,4,4,5,5,3}, 23, "[false,false,true,true]"},
        {6, {2,5,4,5,5,3}, 22, "[true,false,true,true]"},
        {6, {2,6,4,5,5,3}, 22, "[null,false,true,true]"},
        {6, {2,7,4,5,5,3}, 19, "[1,false,true,true]"},
        {6, {2,8,4,5,5,3}, 20, "[\"\",false,true,true]"},
        {6, {2,4,5,5,5,3}, 22, "[false,true,true,true]"},
        {6, {2,5,5,5,5,3}, 21, "[true,true,true,true]"},
        {6, {2,6,5,5,5,3}, 21, "[null,true,true,true]"},
        {6, {2,7,5,5,5,3}, 18, "[1,true,true,true]"},
        {6, {2,8,5,5,5,3}, 19, "[\"\",true,true,true]"},
        {6, {2,4,6,5,5,3}, 22, "[false,null,true,true]"},
        {6, {2,5,6,5,5,3}, 21, "[true,null,true,true]"},
        {6, {2,6,6,5,5,3}, 21, "[null,null,true,true]"},
        {6, {2,7,6,5,5,3}, 18, "[1,null,true,true]"},
        {6, {2,8,6,5,5,3}, 19, "[\"\",null,true,true]"},
        {6, {2,4,7,5,5,3}, 19, "[false,2,true,true]"},
        {6, {2,5,7,5,5,3}, 18, "[true,2,true,true]"},
        {6, {2,6,7,5,5,3}, 18, "[null,2,true,true]"},
        {6, {2,7,7,5,5,3}, 15, "[1,2,true,true]"},
        {6, {2,8,7,5,5,3}, 16, "[\"\",2,true,true]"},
        {6, {2,4,8,5,5,3}, 20, "[false,\"\",true,true]"},
        {6, {2,5,8,5,5,3}, 19, "[true,\"\",true,true]"},
        {6, {2,6,8,5,5,3}, 19, "[null,\"\",true,true]"},
        {6, {2,7,8,5,5,3}, 16, "[1,\"\",true,true]"},
        {6, {2,8,8,5,5,3}, 17, "[\"\",\"\",true,true]"},
        {6, {2,0,1,6,5,3}, 14, "[{},null,true]"},
        {6, {2,2,3,6,5,3}, 14, "[[],null,true]"},
        {6, {2,4,4,6,5,3}, 23, "[false,false,null,true]"},
        {6, {2,5,4,6,5,3}, 22, "[true,false,null,true]"},
        {6, {2,6,4,6,5,3}, 22, "[null,false,null,true]"},
        {6, {2,7,4,6,5,3}, 19, "[1,false,null,true]"},
        {6, {2,8,4,6,5,3}, 20, "[\"\",false,null,true]"},
        {6, {2,4,5,6,5,3}, 22, "[false,true,null,true]"},
        {6, {2,5,5,6,5,3}, 21, "[true,true,null,true]"},
        {6, {2,6,5,6,5,3}, 21, "[null,true,null,true]"},
        {6, {2,7,5,6,5,3}, 18, "[1,true,null,true]"},
        {6, {2,8,5,6,5,3}, 19, "[\"\",true,null,true]"},
        {6, {2,4,6,6,5,3}, 22, "[false,null,null,true]"},
        {6, {2,5,6,6,5,3}, 21, "[true,null,null,true]"},
        {6, {2,6,6,6,5,3}, 21, "[null,null,null,true]"},
        {6, {2,7,6,6,5,3}, 18, "[1,null,null,true]"},
        {6, {2,8,6,6,5,3}, 19, "[\"\",null,null,true]"},
        {6, {2,4,7,6,5,3}, 19, "[false,2,null,true]"},
        {6, {2,5,7,6,5,3}, 18, "[true,2,null,true]"},
        {6, {2,6,7,6,5,3}, 18, "[null,2,null,true]"},
        {6, {2,7,7,6,5,3}, 15, "[1,2,null,true]"},
        {6, {2,8,7,6,5,3}, 16, "[\"\",2,null,true]"},
        {6, {2,4,8,6,5,3}, 20, "[false,\"\",null,true]"},
        {6, {2,5,8,6,5,3}, 19, "[true,\"\",null,true]"},
        {6, {2,6,8,6,5,3}, 19, "[null,\"\",null,true]"},
        {6, {2,7,8,6,5,3}, 16, "[1,\"\",null,true]"},
        {6, {2,8,8,6,5,3}, 17, "[\"\",\"\",null,true]"},
        {6, {2,0,1,7,5,3}, 11, "[{},3,true]"},
        {6, {2,2,3,7,5,3}, 11, "[[],3,true]"},
        {6, {2,4,4,7,5,3}, 20, "[false,false,3,true]"},
        {6, {2,5,4,7,5,3}, 19, "[true,false,3,true]"},
        {6, {2,6,4,7,5,3}, 19, "[null,false,3,true]"},
        {6, {2,7,4,7,5,3}, 16, "[1,false,3,true]"},
        {6, {2,8,4,7,5,3}, 17, "[\"\",false,3,true]"},
        {6, {2,4,5,7,5,3}, 19, "[false,true,3,true]"},
        {6, {2,5,5,7,5,3}, 18, "[true,true,3,true]"},
        {6, {2,6,5,7,5,3}, 18, "[null,true,3,true]"},
        {6, {2,7,5,7,5,3}, 15, "[1,true,3,true]"},
        {6, {2,8,5,7,5,3}, 16, "[\"\",true,3,true]"},
        {6, {2,4,6,7,5,3}, 19, "[false,null,3,true]"},
        {6, {2,5,6,7,5,3}, 18, "[true,null,3,true]"},
        {6, {2,6,6,7,5,3}, 18, "[null,null,3,true]"},
        {6, {2,7,6,7,5,3}, 15, "[1,null,3,true]"},
        {6, {2,8,6,7,5,3}, 16, "[\"\",null,3,true]"},
        {6, {2,4,7,7,5,3}, 16, "[false,2,3,true]"},
        {6, {2,5,7,7,5,3}, 15, "[true,2,3,true]"},
        {6, {2,6,7,7,5,3}, 15, "[null,2,3,true]"},
        {6, {2,7,7,7,5,3}, 12, "[1,2,3,true]"},
        {6, {2,8,7,7,5,3}, 13, "[\"\",2,3,true]"},
        {6, {2,4,8,7,5,3}, 17, "[false,\"\",3,true]"},
        {6, {2,5,8,7,5,3}, 16, "[true,\"\",3,true]"},
        {6, {2,6,8,7,5,3}, 16, "[null,\"\",3,true]"},
        {6, {2,7,8,7,5,3}, 13, "[1,\"\",3,true]"},
        {6, {2,8,8,7,5,3}, 14, "[\"\",\"\",3,true]"},
        {6, {2,0,1,8,5,3}, 12, "[{},\"\",true]"},
        {6, {2,2,3,8,5,3}, 12, "[[],\"\",true]"},
        {6, {2,4,4,8,5,3}, 21, "[false,false,\"\",true]"},
        {6, {2,5,4,8,5,3}, 20, "[true,false,\"\",true]"},
        {6, {2,6,4,8,5,3}, 20, "[null,false,\"\",true]"},
        {6, {2,7,4,8,5,3}, 17, "[1,false,\"\",true]"},
        {6, {2,8,4,8,5,3}, 18, "[\"\",false,\"\",true]"},
        {6, {2,4,5,8,5,3}, 20, "[false,true,\"\",true]"},
        {6, {2,5,5,8,5,3}, 19, "[true,true,\"\",true]"},
        {6, {2,6,5,8,5,3}, 19, "[null,true,\"\",true]"},
        {6, {2,7,5,8,5,3}, 16, "[1,true,\"\",true]"},
        {6, {2,8,5,8,5,3}, 17, "[\"\",true,\"\",true]"},
        {6, {2,4,6,8,5,3}, 20, "[false,null,\"\",true]"},
        {6, {2,5,6,8,5,3}, 19, "[true,null,\"\",true]"},
        {6, {2,6,6,8,5,3}, 19, "[null,null,\"\",true]"},
        {6, {2,7,6,8,5,3}, 16, "[1,null,\"\",true]"},
        {6, {2,8,6,8,5,3}, 17, "[\"\",null,\"\",true]"},
        {6, {2,4,7,8,5,3}, 17, "[false,2,\"\",true]"},
        {6, {2,5,7,8,5,3}, 16, "[true,2,\"\",true]"},
        {6, {2,6,7,8,5,3}, 16, "[null,2,\"\",true]"},
        {6, {2,7,7,8,5,3}, 13, "[1,2,\"\",true]"},
        {6, {2,8,7,8,5,3}, 14, "[\"\",2,\"\",true]"},
        {6, {2,4,8,8,5,3}, 18, "[false,\"\",\"\",true]"},
        {6, {2,5,8,8,5,3}, 17, "[true,\"\",\"\",true]"},
        {6, {2,6,8,8,5,3}, 17, "[null,\"\",\"\",true]"},
        {6, {2,7,8,8,5,3}, 14, "[1,\"\",\"\",true]"},
        {6, {2,8,8,8,5,3}, 15, "[\"\",\"\",\"\",true]"},
        {6, {2,4,0,1,6,3}, 15, "[false,{},null]"},
        {6, {2,5,0,1,6,3}, 14, "[true,{},null]"},
        {6, {2,6,0,1,6,3}, 14, "[null,{},null]"},
        {6, {2,7,0,1,6,3}, 11, "[1,{},null]"},
        {6, {2,8,0,1,6,3}, 12, "[\"\",{},null]"},
        {6, {2,4,2,3,6,3}, 15, "[false,[],null]"},
        {6, {2,5,2,3,6,3}, 14, "[true,[],null]"},
        {6, {2,6,2,3,6,3}, 14, "[null,[],null]"},
        {6, {2,7,2,3,6,3}, 11, "[1,[],null]"},
        {6, {2,8,2,3,6,3}, 12, "[\"\",[],null]"},
        {6, {2,2,4,3,6,3}, 14, "[[false],null]"},
        {6, {2,2,5,3,6,3}, 13, "[[true],null]"},
        {6, {2,2,6,3,6,3}, 13, "[[null],null]"},
        {6, {2,2,7,3,6,3}, 10, "[[2],null]"},
        {6, {2,2,8,3,6,3}, 11, "[[\"\"],null]"},
        {6, {2,0,1,4,6,3}, 15, "[{},false,null]"},
        {6, {2,2,3,4,6,3}, 15, "[[],false,null]"},
        {6, {2,4,4,4,6,3}, 24, "[false,false,false,null]"},
        {6, {2,5,4,4,6,3}, 23, "[true,false,false,null]"},
        {6, {2,6,4,4,6,3}, 23, "[null,false,false,null]"},
        {6, {2,7,4,4,6,3}, 20, "[1,false,false,null]"},
        {6, {2,8,4,4,6,3}, 21, "[\"\",false,false,null]"},
        {6, {2,4,5,4,6,3}, 23, "[false,true,false,null]"},
        {6, {2,5,5,4,6,3}, 22, "[true,true,false,null]"},
        {6, {2,6,5,4,6,3}, 22, "[null,true,false,null]"},
        {6, {2,7,5,4,6,3}, 19, "[1,true,false,null]"},
        {6, {2,8,5,4,6,3}, 20, "[\"\",true,false,null]"},
        {6, {2,4,6,4,6,3}, 23, "[false,null,false,null]"},
        {6, {2,5,6,4,6,3}, 22, "[true,null,false,null]"},
        {6, {2,6,6,4,6,3}, 22, "[null,null,false,null]"},
        {6, {2,7,6,4,6,3}, 19, "[1,null,false,null]"},
        {6, {2,8,6,4,6,3}, 20, "[\"\",null,false,null]"},
        {6, {2,4,7,4,6,3}, 20, "[false,2,false,null]"},
        {6, {2,5,7,4,6,3}, 19, "[true,2,false,null]"},
        {6, {2,6,7,4,6,3}, 19, "[null,2,false,null]"},
        {6, {2,7,7,4,6,3}, 16, "[1,2,false,null]"},
        {6, {2,8,7,4,6,3}, 17, "[\"\",2,false,null]"},
        {6, {2,4,8,4,6,3}, 21, "[false,\"\",false,null]"},
        {6, {2,5,8,4,6,3}, 20, "[true,\"\",false,null]"},
        {6, {2,6,8,4,6,3}, 20, "[null,\"\",false,null]"},
        {6, {2,7,8,4,6,3}, 17, "[1,\"\",false,null]"},
        {6, {2,8,8,4,6,3}, 18, "[\"\",\"\",false,null]"},
        {6, {2,0,1,5,6,3}, 14, "[{},true,null]"},
        {6, {2,2,3,5,6,3}, 14, "[[],true,null]"},
        {6, {2,4,4,5,6,3}, 23, "[false,false,true,null]"},
        {6, {2,5,4,5,6,3}, 22, "[true,false,true,null]"},
        {6, {2,6,4,5,6,3}, 22, "[null,false,true,null]"},
        {6, {2,7,4,5,6,3}, 19, "[1,false,true,null]"},
        {6, {2,8,4,5,6,3}, 20, "[\"\",false,true,null]"},
        {6, {2,4,5,5,6,3}, 22, "[false,true,true,null]"},
        {6, {2,5,5,5,6,3}, 21, "[true,true,true,null]"},
        {6, {2,6,5,5,6,3}, 21, "[null,true,true,null]"},
        {6, {2,7,5,5,6,3}, 18, "[1,true,true,null]"},
        {6, {2,8,5,5,6,3}, 19, "[\"\",true,true,null]"},
        {6, {2,4,6,5,6,3}, 22, "[false,null,true,null]"},
        {6, {2,5,6,5,6,3}, 21, "[true,null,true,null]"},
        {6, {2,6,6,5,6,3}, 21, "[null,null,true,null]"},
        {6, {2,7,6,5,6,3}, 18, "[1,null,true,null]"},
        {6, {2,8,6,5,6,3}, 19, "[\"\",null,true,null]"},
        {6, {2,4,7,5,6,3}, 19, "[false,2,true,null]"},
        {6, {2,5,7,5,6,3}, 18, "[true,2,true,null]"},
        {6, {2,6,7,5,6,3}, 18, "[null,2,true,null]"},
        {6, {2,7,7,5,6,3}, 15, "[1,2,true,null]"},
        {6, {2,8,7,5,6,3}, 16, "[\"\",2,true,null]"},
        {6, {2,4,8,5,6,3}, 20, "[false,\"\",true,null]"},
        {6, {2,5,8,5,6,3}, 19, "[true,\"\",true,null]"},
        {6, {2,6,8,5,6,3}, 19, "[null,\"\",true,null]"},
        {6, {2,7,8,5,6,3}, 16, "[1,\"\",true,null]"},
        {6, {2,8,8,5,6,3}, 17, "[\"\",\"\",true,null]"},
        {6, {2,0,1,6,6,3}, 14, "[{},null,null]"},
        {6, {2,2,3,6,6,3}, 14, "[[],null,null]"},
        {6, {2,4,4,6,6,3}, 23, "[false,false,null,null]"},
        {6, {2,5,4,6,6,3}, 22, "[true,false,null,null]"},
        {6, {2,6,4,6,6,3}, 22, "[null,false,null,null]"},
        {6, {2,7,4,6,6,3}, 19, "[1,false,null,null]"},
        {6, {2,8,4,6,6,3}, 20, "[\"\",false,null,null]"},
        {6, {2,4,5,6,6,3}, 22, "[false,true,null,null]"},
        {6, {2,5,5,6,6,3}, 21, "[true,true,null,null]"},
        {6, {2,6,5,6,6,3}, 21, "[null,true,null,null]"},
        {6, {2,7,5,6,6,3}, 18, "[1,true,null,null]"},
        {6, {2,8,5,6,6,3}, 19, "[\"\",true,null,null]"},
        {6, {2,4,6,6,6,3}, 22, "[false,null,null,null]"},
        {6, {2,5,6,6,6,3}, 21, "[true,null,null,null]"},
        {6, {2,6,6,6,6,3}, 21, "[null,null,null,null]"},
        {6, {2,7,6,6,6,3}, 18, "[1,null,null,null]"},
        {6, {2,8,6,6,6,3}, 19, "[\"\",null,null,null]"},
        {6, {2,4,7,6,6,3}, 19, "[false,2,null,null]"},
        {6, {2,5,7,6,6,3}, 18, "[true,2,null,null]"},
        {6, {2,6,7,6,6,3}, 18, "[null,2,null,null]"},
        {6, {2,7,7,6,6,3}, 15, "[1,2,null,null]"},
        {6, {2,8,7,6,6,3}, 16, "[\"\",2,null,null]"},
        {6, {2,4,8,6,6,3}, 20, "[false,\"\",null,null]"},
        {6, {2,5,8,6,6,3}, 19, "[true,\"\",null,null]"},
        {6, {2,6,8,6,6,3}, 19, "[null,\"\",null,null]"},
        {6, {2,7,8,6,6,3}, 16, "[1,\"\",null,null]"},
        {6, {2,8,8,6,6,3}, 17, "[\"\",\"\",null,null]"},
        {6, {2,0,1,7,6,3}, 11, "[{},3,null]"},
        {6, {2,2,3,7,6,3}, 11, "[[],3,null]"},
        {6, {2,4,4,7,6,3}, 20, "[false,false,3,null]"},
        {6, {2,5,4,7,6,3}, 19, "[true,false,3,null]"},
        {6, {2,6,4,7,6,3}, 19, "[null,false,3,null]"},
        {6, {2,7,4,7,6,3}, 16, "[1,false,3,null]"},
        {6, {2,8,4,7,6,3}, 17, "[\"\",false,3,null]"},
        {6, {2,4,5,7,6,3}, 19, "[false,true,3,null]"},
        {6, {2,5,5,7,6,3}, 18, "[true,true,3,null]"},
        {6, {2,6,5,7,6,3}, 18, "[null,true,3,null]"},
        {6, {2,7,5,7,6,3}, 15, "[1,true,3,null]"},
        {6, {2,8,5,7,6,3}, 16, "[\"\",true,3,null]"},
        {6, {2,4,6,7,6,3}, 19, "[false,null,3,null]"},
        {6, {2,5,6,7,6,3}, 18, "[true,null,3,null]"},
        {6, {2,6,6,7,6,3}, 18, "[null,null,3,null]"},
        {6, {2,7,6,7,6,3}, 15, "[1,null,3,null]"},
        {6, {2,8,6,7,6,3}, 16, "[\"\",null,3,null]"},
        {6, {2,4,7,7,6,3}, 16, "[false,2,3,null]"},
        {6, {2,5,7,7,6,3}, 15, "[true,2,3,null]"},
        {6, {2,6,7,7,6,3}, 15, "[null,2,3,null]"},
        {6, {2,7,7,7,6,3}, 12, "[1,2,3,null]"},
        {6, {2,8,7,7,6,3}, 13, "[\"\",2,3,null]"},
        {6, {2,4,8,7,6,3}, 17, "[false,\"\",3,null]"},
        {6, {2,5,8,7,6,3}, 16, "[true,\"\",3,null]"},
        {6, {2,6,8,7,6,3}, 16, "[null,\"\",3,null]"},
        {6, {2,7,8,7,6,3}, 13, "[1,\"\",3,null]"},
        {6, {2,8,8,7,6,3}, 14, "[\"\",\"\",3,null]"},
        {6, {2,0,1,8,6,3}, 12, "[{},\"\",null]"},
        {6, {2,2,3,8,6,3}, 12, "[[],\"\",null]"},
        {6, {2,4,4,8,6,3}, 21, "[false,false,\"\",null]"},
        {6, {2,5,4,8,6,3}, 20, "[true,false,\"\",null]"},
        {6, {2,6,4,8,6,3}, 20, "[null,false,\"\",null]"},
        {6, {2,7,4,8,6,3}, 17, "[1,false,\"\",null]"},
        {6, {2,8,4,8,6,3}, 18, "[\"\",false,\"\",null]"},
        {6, {2,4,5,8,6,3}, 20, "[false,true,\"\",null]"},
        {6, {2,5,5,8,6,3}, 19, "[true,true,\"\",null]"},
        {6, {2,6,5,8,6,3}, 19, "[null,true,\"\",null]"},
        {6, {2,7,5,8,6,3}, 16, "[1,true,\"\",null]"},
        {6, {2,8,5,8,6,3}, 17, "[\"\",true,\"\",null]"},
        {6, {2,4,6,8,6,3}, 20, "[false,null,\"\",null]"},
        {6, {2,5,6,8,6,3}, 19, "[true,null,\"\",null]"},
        {6, {2,6,6,8,6,3}, 19, "[null,null,\"\",null]"},
        {6, {2,7,6,8,6,3}, 16, "[1,null,\"\",null]"},
        {6, {2,8,6,8,6,3}, 17, "[\"\",null,\"\",null]"},
        {6, {2,4,7,8,6,3}, 17, "[false,2,\"\",null]"},
        {6, {2,5,7,8,6,3}, 16, "[true,2,\"\",null]"},
        {6, {2,6,7,8,6,3}, 16, "[null,2,\"\",null]"},
        {6, {2,7,7,8,6,3}, 13, "[1,2,\"\",null]"},
        {6, {2,8,7,8,6,3}, 14, "[\"\",2,\"\",null]"},
        {6, {2,4,8,8,6,3}, 18, "[false,\"\",\"\",null]"},
        {6, {2,5,8,8,6,3}, 17, "[true,\"\",\"\",null]"},
        {6, {2,6,8,8,6,3}, 17, "[null,\"\",\"\",null]"},
        {6, {2,7,8,8,6,3}, 14, "[1,\"\",\"\",null]"},
        {6, {2,8,8,8,6,3}, 15, "[\"\",\"\",\"\",null]"},
        {6, {2,4,0,1,7,3}, 12, "[false,{},4]"},
        {6, {2,5,0,1,7,3}, 11, "[true,{},4]"},
        {6, {2,6,0,1,7,3}, 11, "[null,{},4]"},
        {6, {2,7,0,1,7,3}, 8,  "[1,{},4]"},
        {6, {2,8,0,1,7,3}, 9,  "[\"\",{},4]"},
        {6, {2,4,2,3,7,3}, 12, "[false,[],4]"},
        {6, {2,5,2,3,7,3}, 11, "[true,[],4]"},
        {6, {2,6,2,3,7,3}, 11, "[null,[],4]"},
        {6, {2,7,2,3,7,3}, 8,  "[1,[],4]"},
        {6, {2,8,2,3,7,3}, 9,  "[\"\",[],4]"},
        {6, {2,2,4,3,7,3}, 11, "[[false],4]"},
        {6, {2,2,5,3,7,3}, 10, "[[true],4]"},
        {6, {2,2,6,3,7,3}, 10, "[[null],4]"},
        {6, {2,2,7,3,7,3}, 7,  "[[2],4]"},
        {6, {2,2,8,3,7,3}, 8,  "[[\"\"],4]"},
        {6, {2,0,1,4,7,3}, 12, "[{},false,4]"},
        {6, {2,2,3,4,7,3}, 12, "[[],false,4]"},
        {6, {2,4,4,4,7,3}, 21, "[false,false,false,4]"},
        {6, {2,5,4,4,7,3}, 20, "[true,false,false,4]"},
        {6, {2,6,4,4,7,3}, 20, "[null,false,false,4]"},
        {6, {2,7,4,4,7,3}, 17, "[1,false,false,4]"},
        {6, {2,8,4,4,7,3}, 18, "[\"\",false,false,4]"},
        {6, {2,4,5,4,7,3}, 20, "[false,true,false,4]"},
        {6, {2,5,5,4,7,3}, 19, "[true,true,false,4]"},
        {6, {2,6,5,4,7,3}, 19, "[null,true,false,4]"},
        {6, {2,7,5,4,7,3}, 16, "[1,true,false,4]"},
        {6, {2,8,5,4,7,3}, 17, "[\"\",true,false,4]"},
        {6, {2,4,6,4,7,3}, 20, "[false,null,false,4]"},
        {6, {2,5,6,4,7,3}, 19, "[true,null,false,4]"},
        {6, {2,6,6,4,7,3}, 19, "[null,null,false,4]"},
        {6, {2,7,6,4,7,3}, 16, "[1,null,false,4]"},
        {6, {2,8,6,4,7,3}, 17, "[\"\",null,false,4]"},
        {6, {2,4,7,4,7,3}, 17, "[false,2,false,4]"},
        {6, {2,5,7,4,7,3}, 16, "[true,2,false,4]"},
        {6, {2,6,7,4,7,3}, 16, "[null,2,false,4]"},
        {6, {2,7,7,4,7,3}, 13, "[1,2,false,4]"},
        {6, {2,8,7,4,7,3}, 14, "[\"\",2,false,4]"},
        {6, {2,4,8,4,7,3}, 18, "[false,\"\",false,4]"},
        {6, {2,5,8,4,7,3}, 17, "[true,\"\",false,4]"},
        {6, {2,6,8,4,7,3}, 17, "[null,\"\",false,4]"},
        {6, {2,7,8,4,7,3}, 14, "[1,\"\",false,4]"},
        {6, {2,8,8,4,7,3}, 15, "[\"\",\"\",false,4]"},
        {6, {2,0,1,5,7,3}, 11, "[{},true,4]"},
        {6, {2,2,3,5,7,3}, 11, "[[],true,4]"},
        {6, {2,4,4,5,7,3}, 20, "[false,false,true,4]"},
        {6, {2,5,4,5,7,3}, 19, "[true,false,true,4]"},
        {6, {2,6,4,5,7,3}, 19, "[null,false,true,4]"},
        {6, {2,7,4,5,7,3}, 16, "[1,false,true,4]"},
        {6, {2,8,4,5,7,3}, 17, "[\"\",false,true,4]"},
        {6, {2,4,5,5,7,3}, 19, "[false,true,true,4]"},
        {6, {2,5,5,5,7,3}, 18, "[true,true,true,4]"},
        {6, {2,6,5,5,7,3}, 18, "[null,true,true,4]"},
        {6, {2,7,5,5,7,3}, 15, "[1,true,true,4]"},
        {6, {2,8,5,5,7,3}, 16, "[\"\",true,true,4]"},
        {6, {2,4,6,5,7,3}, 19, "[false,null,true,4]"},
        {6, {2,5,6,5,7,3}, 18, "[true,null,true,4]"},
        {6, {2,6,6,5,7,3}, 18, "[null,null,true,4]"},
        {6, {2,7,6,5,7,3}, 15, "[1,null,true,4]"},
        {6, {2,8,6,5,7,3}, 16, "[\"\",null,true,4]"},
        {6, {2,4,7,5,7,3}, 16, "[false,2,true,4]"},
        {6, {2,5,7,5,7,3}, 15, "[true,2,true,4]"},
        {6, {2,6,7,5,7,3}, 15, "[null,2,true,4]"},
        {6, {2,7,7,5,7,3}, 12, "[1,2,true,4]"},
        {6, {2,8,7,5,7,3}, 13, "[\"\",2,true,4]"},
        {6, {2,4,8,5,7,3}, 17, "[false,\"\",true,4]"},
        {6, {2,5,8,5,7,3}, 16, "[true,\"\",true,4]"},
        {6, {2,6,8,5,7,3}, 16, "[null,\"\",true,4]"},
        {6, {2,7,8,5,7,3}, 13, "[1,\"\",true,4]"},
        {6, {2,8,8,5,7,3}, 14, "[\"\",\"\",true,4]"},
        {6, {2,0,1,6,7,3}, 11, "[{},null,4]"},
        {6, {2,2,3,6,7,3}, 11, "[[],null,4]"},
        {6, {2,4,4,6,7,3}, 20, "[false,false,null,4]"},
        {6, {2,5,4,6,7,3}, 19, "[true,false,null,4]"},
        {6, {2,6,4,6,7,3}, 19, "[null,false,null,4]"},
        {6, {2,7,4,6,7,3}, 16, "[1,false,null,4]"},
        {6, {2,8,4,6,7,3}, 17, "[\"\",false,null,4]"},
        {6, {2,4,5,6,7,3}, 19, "[false,true,null,4]"},
        {6, {2,5,5,6,7,3}, 18, "[true,true,null,4]"},
        {6, {2,6,5,6,7,3}, 18, "[null,true,null,4]"},
        {6, {2,7,5,6,7,3}, 15, "[1,true,null,4]"},
        {6, {2,8,5,6,7,3}, 16, "[\"\",true,null,4]"},
        {6, {2,4,6,6,7,3}, 19, "[false,null,null,4]"},
        {6, {2,5,6,6,7,3}, 18, "[true,null,null,4]"},
        {6, {2,6,6,6,7,3}, 18, "[null,null,null,4]"},
        {6, {2,7,6,6,7,3}, 15, "[1,null,null,4]"},
        {6, {2,8,6,6,7,3}, 16, "[\"\",null,null,4]"},
        {6, {2,4,7,6,7,3}, 16, "[false,2,null,4]"},
        {6, {2,5,7,6,7,3}, 15, "[true,2,null,4]"},
        {6, {2,6,7,6,7,3}, 15, "[null,2,null,4]"},
        {6, {2,7,7,6,7,3}, 12, "[1,2,null,4]"},
        {6, {2,8,7,6,7,3}, 13, "[\"\",2,null,4]"},
        {6, {2,4,8,6,7,3}, 17, "[false,\"\",null,4]"},
        {6, {2,5,8,6,7,3}, 16, "[true,\"\",null,4]"},
        {6, {2,6,8,6,7,3}, 16, "[null,\"\",null,4]"},
        {6, {2,7,8,6,7,3}, 13, "[1,\"\",null,4]"},
        {6, {2,8,8,6,7,3}, 14, "[\"\",\"\",null,4]"},
        {6, {2,0,1,7,7,3}, 8,  "[{},3,4]"},
        {6, {2,2,3,7,7,3}, 8,  "[[],3,4]"},
        {6, {2,4,4,7,7,3}, 17, "[false,false,3,4]"},
        {6, {2,5,4,7,7,3}, 16, "[true,false,3,4]"},
        {6, {2,6,4,7,7,3}, 16, "[null,false,3,4]"},
        {6, {2,7,4,7,7,3}, 13, "[1,false,3,4]"},
        {6, {2,8,4,7,7,3}, 14, "[\"\",false,3,4]"},
        {6, {2,4,5,7,7,3}, 16, "[false,true,3,4]"},
        {6, {2,5,5,7,7,3}, 15, "[true,true,3,4]"},
        {6, {2,6,5,7,7,3}, 15, "[null,true,3,4]"},
        {6, {2,7,5,7,7,3}, 12, "[1,true,3,4]"},
        {6, {2,8,5,7,7,3}, 13, "[\"\",true,3,4]"},
        {6, {2,4,6,7,7,3}, 16, "[false,null,3,4]"},
        {6, {2,5,6,7,7,3}, 15, "[true,null,3,4]"},
        {6, {2,6,6,7,7,3}, 15, "[null,null,3,4]"},
        {6, {2,7,6,7,7,3}, 12, "[1,null,3,4]"},
        {6, {2,8,6,7,7,3}, 13, "[\"\",null,3,4]"},
        {6, {2,4,7,7,7,3}, 13, "[false,2,3,4]"},
        {6, {2,5,7,7,7,3}, 12, "[true,2,3,4]"},
        {6, {2,6,7,7,7,3}, 12, "[null,2,3,4]"},
        {6, {2,7,7,7,7,3}, 9,  "[1,2,3,4]"},
        {6, {2,8,7,7,7,3}, 10, "[\"\",2,3,4]"},
        {6, {2,4,8,7,7,3}, 14, "[false,\"\",3,4]"},
        {6, {2,5,8,7,7,3}, 13, "[true,\"\",3,4]"},
        {6, {2,6,8,7,7,3}, 13, "[null,\"\",3,4]"},
        {6, {2,7,8,7,7,3}, 10, "[1,\"\",3,4]"},
        {6, {2,8,8,7,7,3}, 11, "[\"\",\"\",3,4]"},
        {6, {2,0,1,8,7,3}, 9,  "[{},\"\",4]"},
        {6, {2,2,3,8,7,3}, 9,  "[[],\"\",4]"},
        {6, {2,4,4,8,7,3}, 18, "[false,false,\"\",4]"},
        {6, {2,5,4,8,7,3}, 17, "[true,false,\"\",4]"},
        {6, {2,6,4,8,7,3}, 17, "[null,false,\"\",4]"},
        {6, {2,7,4,8,7,3}, 14, "[1,false,\"\",4]"},
        {6, {2,8,4,8,7,3}, 15, "[\"\",false,\"\",4]"},
        {6, {2,4,5,8,7,3}, 17, "[false,true,\"\",4]"},
        {6, {2,5,5,8,7,3}, 16, "[true,true,\"\",4]"},
        {6, {2,6,5,8,7,3}, 16, "[null,true,\"\",4]"},
        {6, {2,7,5,8,7,3}, 13, "[1,true,\"\",4]"},
        {6, {2,8,5,8,7,3}, 14, "[\"\",true,\"\",4]"},
        {6, {2,4,6,8,7,3}, 17, "[false,null,\"\",4]"},
        {6, {2,5,6,8,7,3}, 16, "[true,null,\"\",4]"},
        {6, {2,6,6,8,7,3}, 16, "[null,null,\"\",4]"},
        {6, {2,7,6,8,7,3}, 13, "[1,null,\"\",4]"},
        {6, {2,8,6,8,7,3}, 14, "[\"\",null,\"\",4]"},
        {6, {2,4,7,8,7,3}, 14, "[false,2,\"\",4]"},
        {6, {2,5,7,8,7,3}, 13, "[true,2,\"\",4]"},
        {6, {2,6,7,8,7,3}, 13, "[null,2,\"\",4]"},
        {6, {2,7,7,8,7,3}, 10, "[1,2,\"\",4]"},
        {6, {2,8,7,8,7,3}, 11, "[\"\",2,\"\",4]"},
        {6, {2,4,8,8,7,3}, 15, "[false,\"\",\"\",4]"},
        {6, {2,5,8,8,7,3}, 14, "[true,\"\",\"\",4]"},
        {6, {2,6,8,8,7,3}, 14, "[null,\"\",\"\",4]"},
        {6, {2,7,8,8,7,3}, 11, "[1,\"\",\"\",4]"},
        {6, {2,8,8,8,7,3}, 12, "[\"\",\"\",\"\",4]"},
        {6, {2,4,0,1,8,3}, 13, "[false,{},\"\"]"},
        {6, {2,5,0,1,8,3}, 12, "[true,{},\"\"]"},
        {6, {2,6,0,1,8,3}, 12, "[null,{},\"\"]"},
        {6, {2,7,0,1,8,3}, 9,  "[1,{},\"\"]"},
        {6, {2,8,0,1,8,3}, 10, "[\"\",{},\"\"]"},
        {6, {2,4,2,3,8,3}, 13, "[false,[],\"\"]"},
        {6, {2,5,2,3,8,3}, 12, "[true,[],\"\"]"},
        {6, {2,6,2,3,8,3}, 12, "[null,[],\"\"]"},
        {6, {2,7,2,3,8,3}, 9,  "[1,[],\"\"]"},
        {6, {2,8,2,3,8,3}, 10, "[\"\",[],\"\"]"},
        {6, {2,2,4,3,8,3}, 12, "[[false],\"\"]"},
        {6, {2,2,5,3,8,3}, 11, "[[true],\"\"]"},
        {6, {2,2,6,3,8,3}, 11, "[[null],\"\"]"},
        {6, {2,2,7,3,8,3}, 8,  "[[2],\"\"]"},
        {6, {2,2,8,3,8,3}, 9,  "[[\"\"],\"\"]"},
        {6, {2,0,1,4,8,3}, 13, "[{},false,\"\"]"},
        {6, {2,2,3,4,8,3}, 13, "[[],false,\"\"]"},
        {6, {2,4,4,4,8,3}, 22, "[false,false,false,\"\"]"},
        {6, {2,5,4,4,8,3}, 21, "[true,false,false,\"\"]"},
        {6, {2,6,4,4,8,3}, 21, "[null,false,false,\"\"]"},
        {6, {2,7,4,4,8,3}, 18, "[1,false,false,\"\"]"},
        {6, {2,8,4,4,8,3}, 19, "[\"\",false,false,\"\"]"},
        {6, {2,4,5,4,8,3}, 21, "[false,true,false,\"\"]"},
        {6, {2,5,5,4,8,3}, 20, "[true,true,false,\"\"]"},
        {6, {2,6,5,4,8,3}, 20, "[null,true,false,\"\"]"},
        {6, {2,7,5,4,8,3}, 17, "[1,true,false,\"\"]"},
        {6, {2,8,5,4,8,3}, 18, "[\"\",true,false,\"\"]"},
        {6, {2,4,6,4,8,3}, 21, "[false,null,false,\"\"]"},
        {6, {2,5,6,4,8,3}, 20, "[true,null,false,\"\"]"},
        {6, {2,6,6,4,8,3}, 20, "[null,null,false,\"\"]"},
        {6, {2,7,6,4,8,3}, 17, "[1,null,false,\"\"]"},
        {6, {2,8,6,4,8,3}, 18, "[\"\",null,false,\"\"]"},
        {6, {2,4,7,4,8,3}, 18, "[false,2,false,\"\"]"},
        {6, {2,5,7,4,8,3}, 17, "[true,2,false,\"\"]"},
        {6, {2,6,7,4,8,3}, 17, "[null,2,false,\"\"]"},
        {6, {2,7,7,4,8,3}, 14, "[1,2,false,\"\"]"},
        {6, {2,8,7,4,8,3}, 15, "[\"\",2,false,\"\"]"},
        {6, {2,4,8,4,8,3}, 19, "[false,\"\",false,\"\"]"},
        {6, {2,5,8,4,8,3}, 18, "[true,\"\",false,\"\"]"},
        {6, {2,6,8,4,8,3}, 18, "[null,\"\",false,\"\"]"},
        {6, {2,7,8,4,8,3}, 15, "[1,\"\",false,\"\"]"},
        {6, {2,8,8,4,8,3}, 16, "[\"\",\"\",false,\"\"]"},
        {6, {2,0,1,5,8,3}, 12, "[{},true,\"\"]"},
        {6, {2,2,3,5,8,3}, 12, "[[],true,\"\"]"},
        {6, {2,4,4,5,8,3}, 21, "[false,false,true,\"\"]"},
        {6, {2,5,4,5,8,3}, 20, "[true,false,true,\"\"]"},
        {6, {2,6,4,5,8,3}, 20, "[null,false,true,\"\"]"},
        {6, {2,7,4,5,8,3}, 17, "[1,false,true,\"\"]"},
        {6, {2,8,4,5,8,3}, 18, "[\"\",false,true,\"\"]"},
        {6, {2,4,5,5,8,3}, 20, "[false,true,true,\"\"]"},
        {6, {2,5,5,5,8,3}, 19, "[true,true,true,\"\"]"},
        {6, {2,6,5,5,8,3}, 19, "[null,true,true,\"\"]"},
        {6, {2,7,5,5,8,3}, 16, "[1,true,true,\"\"]"},
        {6, {2,8,5,5,8,3}, 17, "[\"\",true,true,\"\"]"},
        {6, {2,4,6,5,8,3}, 20, "[false,null,true,\"\"]"},
        {6, {2,5,6,5,8,3}, 19, "[true,null,true,\"\"]"},
        {6, {2,6,6,5,8,3}, 19, "[null,null,true,\"\"]"},
        {6, {2,7,6,5,8,3}, 16, "[1,null,true,\"\"]"},
        {6, {2,8,6,5,8,3}, 17, "[\"\",null,true,\"\"]"},
        {6, {2,4,7,5,8,3}, 17, "[false,2,true,\"\"]"},
        {6, {2,5,7,5,8,3}, 16, "[true,2,true,\"\"]"},
        {6, {2,6,7,5,8,3}, 16, "[null,2,true,\"\"]"},
        {6, {2,7,7,5,8,3}, 13, "[1,2,true,\"\"]"},
        {6, {2,8,7,5,8,3}, 14, "[\"\",2,true,\"\"]"},
        {6, {2,4,8,5,8,3}, 18, "[false,\"\",true,\"\"]"},
        {6, {2,5,8,5,8,3}, 17, "[true,\"\",true,\"\"]"},
        {6, {2,6,8,5,8,3}, 17, "[null,\"\",true,\"\"]"},
        {6, {2,7,8,5,8,3}, 14, "[1,\"\",true,\"\"]"},
        {6, {2,8,8,5,8,3}, 15, "[\"\",\"\",true,\"\"]"},
        {6, {2,0,1,6,8,3}, 12, "[{},null,\"\"]"},
        {6, {2,2,3,6,8,3}, 12, "[[],null,\"\"]"},
        {6, {2,4,4,6,8,3}, 21, "[false,false,null,\"\"]"},
        {6, {2,5,4,6,8,3}, 20, "[true,false,null,\"\"]"},
        {6, {2,6,4,6,8,3}, 20, "[null,false,null,\"\"]"},
        {6, {2,7,4,6,8,3}, 17, "[1,false,null,\"\"]"},
        {6, {2,8,4,6,8,3}, 18, "[\"\",false,null,\"\"]"},
        {6, {2,4,5,6,8,3}, 20, "[false,true,null,\"\"]"},
        {6, {2,5,5,6,8,3}, 19, "[true,true,null,\"\"]"},
        {6, {2,6,5,6,8,3}, 19, "[null,true,null,\"\"]"},
        {6, {2,7,5,6,8,3}, 16, "[1,true,null,\"\"]"},
        {6, {2,8,5,6,8,3}, 17, "[\"\",true,null,\"\"]"},
        {6, {2,4,6,6,8,3}, 20, "[false,null,null,\"\"]"},
        {6, {2,5,6,6,8,3}, 19, "[true,null,null,\"\"]"},
        {6, {2,6,6,6,8,3}, 19, "[null,null,null,\"\"]"},
        {6, {2,7,6,6,8,3}, 16, "[1,null,null,\"\"]"},
        {6, {2,8,6,6,8,3}, 17, "[\"\",null,null,\"\"]"},
        {6, {2,4,7,6,8,3}, 17, "[false,2,null,\"\"]"},
        {6, {2,5,7,6,8,3}, 16, "[true,2,null,\"\"]"},
        {6, {2,6,7,6,8,3}, 16, "[null,2,null,\"\"]"},
        {6, {2,7,7,6,8,3}, 13, "[1,2,null,\"\"]"},
        {6, {2,8,7,6,8,3}, 14, "[\"\",2,null,\"\"]"},
        {6, {2,4,8,6,8,3}, 18, "[false,\"\",null,\"\"]"},
        {6, {2,5,8,6,8,3}, 17, "[true,\"\",null,\"\"]"},
        {6, {2,6,8,6,8,3}, 17, "[null,\"\",null,\"\"]"},
        {6, {2,7,8,6,8,3}, 14, "[1,\"\",null,\"\"]"},
        {6, {2,8,8,6,8,3}, 15, "[\"\",\"\",null,\"\"]"},
        {6, {2,0,1,7,8,3}, 9,  "[{},3,\"\"]"},
        {6, {2,2,3,7,8,3}, 9,  "[[],3,\"\"]"},
        {6, {2,4,4,7,8,3}, 18, "[false,false,3,\"\"]"},
        {6, {2,5,4,7,8,3}, 17, "[true,false,3,\"\"]"},
        {6, {2,6,4,7,8,3}, 17, "[null,false,3,\"\"]"},
        {6, {2,7,4,7,8,3}, 14, "[1,false,3,\"\"]"},
        {6, {2,8,4,7,8,3}, 15, "[\"\",false,3,\"\"]"},
        {6, {2,4,5,7,8,3}, 17, "[false,true,3,\"\"]"},
        {6, {2,5,5,7,8,3}, 16, "[true,true,3,\"\"]"},
        {6, {2,6,5,7,8,3}, 16, "[null,true,3,\"\"]"},
        {6, {2,7,5,7,8,3}, 13, "[1,true,3,\"\"]"},
        {6, {2,8,5,7,8,3}, 14, "[\"\",true,3,\"\"]"},
        {6, {2,4,6,7,8,3}, 17, "[false,null,3,\"\"]"},
        {6, {2,5,6,7,8,3}, 16, "[true,null,3,\"\"]"},
        {6, {2,6,6,7,8,3}, 16, "[null,null,3,\"\"]"},
        {6, {2,7,6,7,8,3}, 13, "[1,null,3,\"\"]"},
        {6, {2,8,6,7,8,3}, 14, "[\"\",null,3,\"\"]"},
        {6, {2,4,7,7,8,3}, 14, "[false,2,3,\"\"]"},
        {6, {2,5,7,7,8,3}, 13, "[true,2,3,\"\"]"},
        {6, {2,6,7,7,8,3}, 13, "[null,2,3,\"\"]"},
        {6, {2,7,7,7,8,3}, 10, "[1,2,3,\"\"]"},
        {6, {2,8,7,7,8,3}, 11, "[\"\",2,3,\"\"]"},
        {6, {2,4,8,7,8,3}, 15, "[false,\"\",3,\"\"]"},
        {6, {2,5,8,7,8,3}, 14, "[true,\"\",3,\"\"]"},
        {6, {2,6,8,7,8,3}, 14, "[null,\"\",3,\"\"]"},
        {6, {2,7,8,7,8,3}, 11, "[1,\"\",3,\"\"]"},
        {6, {2,8,8,7,8,3}, 12, "[\"\",\"\",3,\"\"]"},
        {6, {2,0,1,8,8,3}, 10, "[{},\"\",\"\"]"},
        {6, {2,2,3,8,8,3}, 10, "[[],\"\",\"\"]"},
        {6, {2,4,4,8,8,3}, 19, "[false,false,\"\",\"\"]"},
        {6, {2,5,4,8,8,3}, 18, "[true,false,\"\",\"\"]"},
        {6, {2,6,4,8,8,3}, 18, "[null,false,\"\",\"\"]"},
        {6, {2,7,4,8,8,3}, 15, "[1,false,\"\",\"\"]"},
        {6, {2,8,4,8,8,3}, 16, "[\"\",false,\"\",\"\"]"},
        {6, {2,4,5,8,8,3}, 18, "[false,true,\"\",\"\"]"},
        {6, {2,5,5,8,8,3}, 17, "[true,true,\"\",\"\"]"},
        {6, {2,6,5,8,8,3}, 17, "[null,true,\"\",\"\"]"},
        {6, {2,7,5,8,8,3}, 14, "[1,true,\"\",\"\"]"},
        {6, {2,8,5,8,8,3}, 15, "[\"\",true,\"\",\"\"]"},
        {6, {2,4,6,8,8,3}, 18, "[false,null,\"\",\"\"]"},
        {6, {2,5,6,8,8,3}, 17, "[true,null,\"\",\"\"]"},
        {6, {2,6,6,8,8,3}, 17, "[null,null,\"\",\"\"]"},
        {6, {2,7,6,8,8,3}, 14, "[1,null,\"\",\"\"]"},
        {6, {2,8,6,8,8,3}, 15, "[\"\",null,\"\",\"\"]"},
        {6, {2,4,7,8,8,3}, 15, "[false,2,\"\",\"\"]"},
        {6, {2,5,7,8,8,3}, 14, "[true,2,\"\",\"\"]"},
        {6, {2,6,7,8,8,3}, 14, "[null,2,\"\",\"\"]"},
        {6, {2,7,7,8,8,3}, 11, "[1,2,\"\",\"\"]"},
        {6, {2,8,7,8,8,3}, 12, "[\"\",2,\"\",\"\"]"},
        {6, {2,4,8,8,8,3}, 16, "[false,\"\",\"\",\"\"]"},
        {6, {2,5,8,8,8,3}, 15, "[true,\"\",\"\",\"\"]"},
        {6, {2,6,8,8,8,3}, 15, "[null,\"\",\"\",\"\"]"},
        {6, {2,7,8,8,8,3}, 12, "[1,\"\",\"\",\"\"]"},
        {6, {2,8,8,8,8,3}, 13, "[\"\",\"\",\"\",\"\"]"},
    };
    char buf[32];
    struct jsonb b[1];
    int i, n, r = 0, nfails = 0, ntests = sizeof(tests)/sizeof(*tests);

    for (n = 0; n < ntests; n++) {
        b->offset = b->depth = b->stack[0] = 0;
        for (i = 0; i < tests[n].cmdlen; i++) {
            switch (tests[n].cmd[i]) {
            case 0: r |= jsonb_push_object(b, buf, sizeof(buf));       break;
            case 1: r |= jsonb_pop_object(b, buf, sizeof(buf));        break;
            case 2: r |= jsonb_push_array(b, buf, sizeof(buf));        break;
            case 3: r |= jsonb_pop_array(b, buf, sizeof(buf));         break;
            case 4: r |= jsonb_push_bool(b, buf, sizeof(buf), 0);      break;
            case 5: r |= jsonb_push_bool(b, buf, sizeof(buf), 1);      break;
            case 6: r |= jsonb_push_null(b, buf, sizeof(buf));         break;
            case 7: r |= jsonb_push_number(b, buf, sizeof(buf), i);    break;
            case 8: r |= jsonb_push_string(b, buf, sizeof(buf), 0, 0); break;
            }
        }
        if (r || !JSONB_DONE(*b)||
            (int)b->offset != tests[n].outlen ||
            memcmp(tests[n].out, buf, b->offset)) {
            printf("FAIL: test #%d\n", n);
            nfails++;
        }
    }

    if (nfails) {
        return 1;
    }
    puts("All tests pass.");
    return 0;
}
#endif
