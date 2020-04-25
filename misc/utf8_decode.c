/* Branchless UTF-8 decoder automaton
 *
 * This automaton accepts one byte of input at a time, eventually either
 * entering an ACCEPT state (0) and leaving a code point, or entering
 * the REJECT state (-1). The state and code point must be zero on the
 * first call of a new code point.
 *
 * The state value is always in the range -1 to 7.
 *
 * This is free and unencumbered software released into the public domain.
 */

enum { UTF8_ACCEPT = 0, UTF8_REJECT = -1 };

int
utf8_decode(int state, long *cp, int byte)
{
    static const signed char table[8][256] = {
        {+0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1,
         +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1,
         +3, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +4, +2, +2,
         +5, +6, +6, +6, +7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0, +0,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1,
         +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1,
         +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1,
         +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1,
         +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1,
         +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1, +1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2,
         +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2,
         +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2,
         +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2,
         +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2,
         +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2, +2,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}
    };
    static unsigned char masks[2][8] = {
        {0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f},
        {0x7f, 0x1f, 0x0f, 0x0f, 0x0f, 0x07, 0x07, 0x07}
    };
    int next = table[state][byte];
    *cp = (*cp << 6) | (byte & masks[!state][next&7]);
    return next;
}

#ifdef TEST
/* Usage:
 *   $ cc -Os -fsanitize=address -fsanitize=undefined -DTEST utf8.c
 *   $ ./a.out
 */

#include <stdio.h>

#define IS_SURROGATE(c) ((c) >= 0xd800L && (c) <= 0xdfffL)

static void *
utf8_encode(void *buf, long c)
{
    unsigned char *s = buf;
    if (c >= (1L << 16)) {
        s[0] = 0xf0 |  (c >> 18);
        s[1] = 0x80 | ((c >> 12) & 0x3f);
        s[2] = 0x80 | ((c >>  6) & 0x3f);
        s[3] = 0x80 | ((c >>  0) & 0x3f);
        return s + 4;
    } else if (c >= (1L << 11)) {
        s[0] = 0xe0 |  (c >> 12);
        s[1] = 0x80 | ((c >>  6) & 0x3f);
        s[2] = 0x80 | ((c >>  0) & 0x3f);
        return s + 3;
    } else if (c >= (1L << 7)) {
        s[0] = 0xc0 |  (c >>  6);
        s[1] = 0x80 | ((c >>  0) & 0x3f);
        return s + 2;
    } else {
        s[0] = c;
        return s + 1;
    }
}

static int
try_decode(const unsigned char *buf, int len)
{
    long cp = 0;
    int i, state = 0;
    for (i = 0, state = 0; i < len; i++) {
        state = utf8_decode(state, &cp, buf[i]);
        if (state == UTF8_REJECT || state == UTF8_ACCEPT) {
            break;
        }
    }
    return state;
}

int
main(void)
{
    long cp;
    int result = 0;

    for (cp = 0; cp <= 0x1fffff; cp++) {
        long out = 0;
        int state = 0;
        unsigned char *p;
        unsigned char buf[4];
        unsigned char *end = utf8_encode(buf, cp);

        for (p = buf; p < end; p++) {
            state = utf8_decode(state, &out, *p);
            if (state == UTF8_REJECT || state == UTF8_ACCEPT) {
                break;
            }
        }

        if (cp > 0x10ffff) {
            switch (state) {
            case UTF8_ACCEPT:
                printf("FAIL: accepted U+%06lx (as U+%06lx)\n", cp, out);
                result = 1;
                break;
            case UTF8_REJECT:
                break;
            default:
                printf("FAIL: incomplete U+%06lx\n", cp);
                result = 1;
                break;
            }

        } else if (IS_SURROGATE(cp)) {
            switch (state) {
            case UTF8_ACCEPT:
                printf("FAIL: accepted U+%06lx (as U+%06lx)\n", cp, out);
                result = 1;
                break;
            case UTF8_REJECT:
                break;
            default:
                printf("FAIL: incomplete U+%06lx (surrogate)\n", cp);
                result = 1;
                break;
            }

        } else {
            switch (state) {
            case UTF8_ACCEPT:
                if (cp != out) {
                    printf("FAIL: wrong decode U+%06lx != U+%06lx\n", cp, out);
                    result = 1;
                }
                break;
            case UTF8_REJECT:
                printf("FAIL: rejected U+%06lx\n", cp);
                result = 1;
                break;
            default:
                printf("FAIL: incomplete U+%06lx\n", cp);
                result = 1;
                break;
            }

        }
    }

    for (cp = 0; cp <= 0x007fL; cp++) {
        unsigned char buf[4];

        buf[0] = 0xc0 | (cp >> 6);
        buf[1] = 0x80 | (cp & 0x3f);
        switch (try_decode(buf, 2)) {
        case UTF8_ACCEPT:
            printf("FAIL: accepted overly-long (2) U+%06lx\n", cp);
            result = 1;
            break;
        case UTF8_REJECT:
            break;
        default:
            printf("FAIL: incomplete U+%06lx\n", cp);
            result = 1;
            break;
        }

        buf[0] = 0xe0;
        buf[1] = 0x80 | (cp >> 6);
        buf[2] = 0x80 | (cp & 0x3f);
        switch (try_decode(buf, 3)) {
        case UTF8_ACCEPT:
            printf("FAIL: accepted overly-long (3) U+%06lx\n", cp);
            result = 1;
            break;
        case UTF8_REJECT:
            break;
        default:
            printf("FAIL: incomplete U+%06lx\n", cp);
            result = 1;
            break;
        }

        buf[0] = 0xf0;
        buf[1] = 0x80;
        buf[2] = 0x80 | (cp >> 6);
        buf[3] = 0x80 | (cp & 0x3f);
        switch (try_decode(buf, 4)) {
        case UTF8_ACCEPT:
            printf("FAIL: accepted overly-long (4) U+%06lx\n", cp);
            result = 1;
            break;
        case UTF8_REJECT:
            break;
        default:
            printf("FAIL: incomplete U+%06lx\n", cp);
            result = 1;
            break;
        }
    }

    for (cp = 0x0080L; cp <= 0x07ffL; cp++) {
        unsigned char buf[4];

        buf[0] = 0xe0;
        buf[1] = 0x80 | (cp >> 6);
        buf[2] = 0x80 | (cp & 0x3f);
        switch (try_decode(buf, 3)) {
        case UTF8_ACCEPT:
            printf("FAIL: accepted overly-long (3) U+%06lx\n", cp);
            result = 1;
            break;
        case UTF8_REJECT:
            break;
        default:
            printf("FAIL: incomplete U+%06lx\n", cp);
            result = 1;
            break;
        }

        buf[0] = 0xf0;
        buf[1] = 0x80;
        buf[2] = 0x80 | (cp >> 6);
        buf[3] = 0x80 | (cp & 0x3f);
        switch (try_decode(buf, 4)) {
        case UTF8_ACCEPT:
            printf("FAIL: accepted overly-long (4) U+%06lx\n", cp);
            result = 1;
            break;
        case UTF8_REJECT:
            break;
        default:
            printf("FAIL: incomplete U+%06lx\n", cp);
            result = 1;
            break;
        }
    }

    for (cp = 0x0800L; cp <= 0xffffL; cp++) {
        unsigned char buf[4];

        buf[0] = 0xf0;
        buf[1] = 0x80 |  (cp >> 12);
        buf[2] = 0x80 | ((cp >>  6) & 0x3f);
        buf[3] = 0x80 |  (cp & 0x3f);
        switch (try_decode(buf, 4)) {
        case UTF8_ACCEPT:
            printf("FAIL: accepted overly-long (4) U+%06lx\n", cp);
            result = 1;
            break;
        case UTF8_REJECT:
            break;
        default:
            printf("FAIL: incomplete U+%06lx\n", cp);
            result = 1;
            break;
        }
    }

    if (!result) puts("PASS");
    return result;
}

#endif