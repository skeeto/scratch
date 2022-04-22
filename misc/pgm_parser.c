// Input a byte into the PGM (P5) parser state machine, updating the
// width / height / depth array and returning the next state. The
// initial state is zero. A negative return is not a state, but an
// error: PGM_OVERFLOW,  PGM_INVALID. The accept state is PGM_DONE, and
// no further input will be accepted. Dimensions are restricted to the
// given maximum: use something reasonable, not LONG_MAX. Fields may be
// left uninitialized on error.
//
// This parser supports arbitrary whitespace and comments. With a few
// tweaks (state 2) it could support any of the other NetPBM formats.
static int
pgm_parse(int state, int c, long *whd, long max)
{
    #define PGM_OVERFLOW  -2
    #define PGM_INVALID   -1
    #define PGM_DONE      +5
    switch (state) {
    default: return PGM_INVALID;
    case  0: switch (c) {
             default : return PGM_INVALID;
             case 'P': return 1;
             }
    case  1: switch (c) {
             default : return PGM_INVALID;
             case '5': return 2;
             }
    case  2:
    case  3:
    case  4: switch (c) {  // between fields
             default : return 0;
             case '0': case '1': case '2': case '3': case '4':
             case '5': case '6': case '7': case '8': case '9':
                 whd[state-2] = c - '0';
                 return state + 4;
             case ' ': case '\n': case '\r': case '\t':
                 return state;
             case '#':
                 return state + 7;
             }
    case  6:
    case  7:
    case  8: switch (c) {  // dimensions
             default : return PGM_INVALID;
             case ' ': case '\n': case '\r': case '\t':
                 return state - 3;  // possibly PGM_DONE
             case '#':
                 return state + 4;
             case '0': case '1': case '2': case '3': case '4':
             case '5': case '6': case '7': case '8': case '9':
                 whd[state-6] = whd[state-6]*10 + c - '0';
                 if (whd[state-6] > max) return PGM_OVERFLOW;
                 return state;
             }
    case  9:
    case 10:
    case 11: switch (c) {  // comments
             default  : return state;
             case '\n': return state - 7;
             }
    }
}

#ifdef TEST
#include <stdio.h>

int
main(void)
{
    long whd[3];
    for (int state = 0;;) {
        int c = getchar();
        if (c == EOF) {
            fprintf(stderr, "pgm_parser: premature end of input\n");
            return 1;
        }

        state = pgm_parse(state, c, whd, 1000000);
        switch (state) {
        case PGM_OVERFLOW:
            fprintf(stderr, "pgm_parser: dimensions too large\n");
            return 1;
        case PGM_INVALID:
            fprintf(stderr, "pgm_parser: invalid input\n");
            return 1;
        case PGM_DONE:
            printf("width   %ld\n", whd[0]);
            printf("height  %ld\n", whd[1]);
            printf("depth   %ld\n", whd[2]);
            return fflush(stdout) || ferror(stdout);
        }
    }
}
#endif
