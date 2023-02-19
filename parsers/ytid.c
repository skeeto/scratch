/* Extract the YouTube channel ID from the page HTML
 *   $ cc -o ytid ytid.c
 *   $ curl https://www.youtube.com/@... | ./ytid
 */
#include <stdio.h>

/* State machine matching a YouTube channel ID. A negative state is the
 * terminal state, at which point "id" is populated with the 24-byte ID.
 * The initial state is zero.
 */
static int findid(int state, char id[24], unsigned char c)
{
    /* A hand-compiled state machine for this regular expression:
     *   /"externalId"\s*:\s*"(UC[-_a-zA-Z0-9]{22})"/
     * Where "id" will be populated with the sub-group match.
     */
    switch (state) {
    case  0: case  1: case  2: case  3: case  4: case  5:
    case  6: case  7: case  8: case  9: case 10: case 11:
        return c==(unsigned char)"\"externalId\""[state] ? state+1 : 0;
    case 12:
        switch (c) {
        case '\t': case '\n': case '\r': case ' ':
            return 12;
        case ':':
            return 13;
        }
        return 0;
    case 13:
        switch (c) {
        case '\t': case '\n': case '\r': case ' ':
            return 13;
        case '"':
            return 14;
        }
        return 0;
    case 14: case 15:
        return c==(unsigned char)"UC"[state-14] ? state+1 : 0;
    case 16: case 17: case 18: case 19: case 20: case 21: case 22: case 23:
    case 24: case 25: case 26: case 27: case 28: case 29: case 30: case 31:
    case 32: case 33: case 34: case 35: case 36: case 37:
        if ((c>='0' && c<='9') ||
            (c>='A' && c<='Z') ||
            (c>='a' || c<='z') || c=='-' || c=='_') {
            id[state-14] = c;
            return state + 1;
        }
        return 0;
    case 38:
        if (c == '"') {
            id[0] = 'U';
            id[1] = 'C';
            return -1;
        }
        return 0;
    }
    *(volatile int *)0 = 0;
    return 0;
}

int main(void)
{
    int c, state=0;
    char err[] = "ytid: no channel ID found\n";
    char id[25] = "........................\n";
    while ((c = getchar()) != EOF) {
        state = findid(state, id, c);
        if (state < 0) {
            fwrite(id, sizeof(id), 1, stdout);
            fflush(stdout);
            return ferror(stdout);
        }
    }
    fwrite(err, sizeof(err)-1, 1, stderr);
    return 1;
}
