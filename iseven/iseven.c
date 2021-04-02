/* State machine accepting one byte at a time to determine if a string
 * contains an even or odd integer (or neither). The initial state is
 * zero. Input is terminated with a zero byte, rendering a final result.
 * Leading zeros are invalid except for zero itself, and no whitespace
 * is accepted. A leading + or - sign is valid.
 *
 * Returns the next state for most non-zero bytes, or the final result
 * for a terminating zero byte. A result of -1 is an error (invalid
 * input), 0 means odd, and 1 means even. Any other return value is a
 * state (always positive).
 *
 * Similar regex: ^[-+]?([1-9][0-9]*)?[0248]$
 */
int iseven(int state, int c)
{
    switch (state) {
    case  5: switch (c) {
             case '0':
             case '1':
             case '2':
             case '3':
             case '4':
             case '5':
             case '6':
             case '7':
             case '8':
             case '9': break;
             default:  return -1;
             } /* fallthrough */
    case  0: switch (c) {
             case '+':
             case '-': return 5;
             case '0': return 2;
             case '2':
             case '4':
             case '6':
             case '8': return 3;
             case '1':
             case '3':
             case '5':
             case '7':
             case '9': return 4;
             } break;
    case  2: return c == 0 ? 1 : -1;
    case  3: switch (c) {
             case  0 : return 1;
             case '0':
             case '2':
             case '4':
             case '6':
             case '8': return 3;
             case '1':
             case '3':
             case '5':
             case '7':
             case '9': return 4;
             } break;
    case  4: switch (c) {
             case  0 : return 0;
             case '0':
             case '2':
             case '4':
             case '6':
             case '8': return 3;
             case '1':
             case '3':
             case '5':
             case '7':
             case '9': return 4;
             } break;
    }
    return -1;
}

#ifdef TEST
#include <stdio.h>

static int test(const char *s)
{
    int state = 0;
    do {
        state = iseven(state, *s);
    } while (*s++);
    return state;
}

int main(void)
{
    static const struct {
        char input[16];
        int want;
    } table[] = {
        {"0",         1},
        {"1",         0},
        {"2",         1},
        {"+0",        1},
        {"+1",        0},
        {"+2",        1},
        {"+02",      -1},
        {"20",        1},
        {"1024",      1},
        {"-1",        0},
        {"-2",        1},
        {"-0",        1},
        {"-02",      -1},
        {"--1",      -1},
        {"++1",      -1},
        {"1034953",   0},
        {"1023485x", -1},
        {"1023x485", -1},
        {"x2",       -1},
        {"",         -1},
        {"00",       -1},
        {"02",       -1},
    };
    int ntable = sizeof(table) / sizeof(*table);
    int width = sizeof(table[0].input);

    int errors = 0;
    for (int i = 0; i < ntable; i++) {
        int want = table[i].want;
        const char *input = table[i].input;
        int got = test(input);
        const char *r = "\x1b[92;1mPASS\x1b[0m";
        if (got != want) {
            errors++;
            r = "\x1b[91;1mFAIL\x1b[0m";
        }
        printf("%s: %-*swant %+d, got %+d\n", r, width, input, want, got);
    }
    printf("%d of %d tests pass\n", ntable - errors, ntable);

    return !!errors;
}
#endif /* TEST */
