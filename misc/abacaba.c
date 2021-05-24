/* ABACABA state machine
 * Ref: https://redd.it/njxq95
 * This is free and unencumbered software released into the public domain.
 */

/* Compute the next ABACABA state. The initial state is zero, and halt
 * is indicated by returning to the zero state.
 *
 * The state is a 31-bit quantity where bits 0-24 are a bitstack, bits
 * 25-29 are the stack size, and bit 30 is the recursion direction.
 *
 *     D IIIII SSSSSSSSSSSSSSSSSSSSSSSSS
 */
static long
abacaba(long s)
{
    for (;;) {
        long stack = s & 0x1ffffff;
        int i = s>>25 & 0x1f;
        int descending = s>>30;
        int middle = s>>i & 1;

        if (i == 25) {
            // bottom out, descend to the parent
            return 1L<<30 | (i-1L)<<25 | stack;
        } else if (descending && !middle) {
            // output "middle" character, ascend into right branch
            return (i+1L)<<25 | stack | 1L<<i;
        } else if (descending && middle) {
            if (!i) return 0L; // halt
            // descend to parent
            s = 1L<<30 | (i-1L)<<25 | (stack ^ 1L<<i);
        } else {
            // ascend into left branch
            s = (i+1L)<<25 | stack;
        }
    }
}

/* Return the output letter for a given state. */
static int
abacaba_letter(long s)
{
    return 'z' - (s>>25 & 0x1f) + (s>>30 ? -1: +1);
}

/* Usage example */
#include <stdio.h>

int
main(void)
{
    for (long state = abacaba(0); state; state = abacaba(state)) {
        putchar(abacaba_letter(state));
    }
    putchar('\n');
}
