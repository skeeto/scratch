/* Dice notation parser state machine
 *
 *   $ cc -DTEST -O3 -o dice dice.c
 *   $ yes 3d6 | head -n1000000 | ./dice | sort -n | uniq -c |
 *         awk '{printf "%3d %0*d\n", $2, $1/2500, "0"}'
 *
 * This is free and unencumbered software released into the public domain.
 */

#define ROLL_MAX       1000000
#define ROLL_TOO_LARGE -2
#define ROLL_INVALID   -1
#define ROLL_INIT      +0

/* Parse a "NdD+B" roll into a 3-element array. The "+B" bias is
 * optional, and the third element will be zero if not provided.
 *
 * Accepts the next byte of input, b, and returns the next state. The
 * initial state is zero, and it returns either the parser next state
 * (positive) or an error (negative). Pass a final zero as the input to
 * validate that input is complete, which returns 0 on success.
 *
 * The roll array may be initialized to any value.
 */
static int
parse_roll(int state, long roll[3], int b)
{
    switch (state) {
    case 0: case 1: case 2:  /* first digit */
        switch (b) {
        default : return ROLL_INVALID;
        case '1': case '2': case '3': case '4': case '5':
        case '6': case '7': case '8': case '9':
            roll[state] = b - '0';
            return state + 3;
        }
    case 3: case 4: case 5:  /* second digit or delimiter */
        switch (b) {
        default : return ROLL_INVALID;
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            roll += state - 3;
            *roll = *roll*10 + b - '0';
            if (*roll > ROLL_MAX) {
                return ROLL_TOO_LARGE;
            }
            return state;
        case 'd':
            roll[2] = 0;
            return state == 3 ? 1 : ROLL_INVALID;
        case '+':
            return state == 4 ? 2 : ROLL_INVALID;
        case  0 :
            return state >= 4 ? 0 : ROLL_INVALID;
        }
    }
    return *(volatile int *)0 = 0;
}


#if TEST
#include <stdio.h>
#include <time.h>

int
main(void)
{
    long i, r, roll[3];
    int state = 0;
    long long lineno = 1;
    unsigned long long lcg = time(0);

    for (;;) {
        int c = getchar();
        switch (c) {
        case EOF: if (!state) return 0;  /* fallthrough */
        case '\t': case '\r': case '\n': case ' ':
            if (!state) continue;
            if (parse_roll(state, roll, 0) < 0) {
                fprintf(stderr, "<stdin>:%lld: invalid input\n", lineno);
                return 1;
            }
            state = 0;
            lineno++;

            r = roll[2] + roll[0];
            for (i = 0; i < roll[0]; i++) {
                lcg = lcg*0x3243f6a8885a308d + 1;
                r += (lcg>>32) % roll[1];
            }
            printf("%ld\n", r);

            if (c == EOF) return 0;
            break;

        default:
            state = parse_roll(state, roll, c);
            if (state < 0) {
                fprintf(stderr, "<stdin>:%lld: invalid input\n", lineno);
                return 1;
            }
        }
    }
}
#endif
