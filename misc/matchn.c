// State machine matching words within a length range
//   $ cc -o matchn matchn.c
//   $ ./matchn <matchn.c
// This is free and unencumbered software released into the public domain.
#include <stdint.h>

// Matches words between MIN and MAX characters beginning with a letter.
// If C completes a match, the buffer will contain the match, and the
// match length is returned. Otherise it returns a non-positive next
// state. Initialize the state to any non-negative value, including a
// previously-returned length. A zero C indicates end of input.
static int matchn(int state, char *match, int min, int max, unsigned char c)
{
    static const uint32_t alpha[8] = {0x0000,0x00000000,0x07fffffe,0x07fffffe};
    static const uint32_t alnum[8] = {0x0000,0x03ff0000,0x07fffffe,0x07fffffe};
    static const uint32_t split[8] = {0x3e01,0xfc00ffff,0xf8000001,0x78000001};
    int i = c >> 5;
    uint32_t b = (uint32_t)1 << (c&31);
    if (state == -1) {  // middle of a non-match
        return split[i]&b ? 0 : -1;
    } else if (state >= 0) {  // may begin a match
        if (alpha[i]&b) {
            match[0] = c;
            return -2;  // begin matching
        }
        return split[i]&b ? 0 : -1;
    } else if (split[i]&b) {  // end of a match
        return (-state-1)>=min ? -state-1 : 0;
    } else if ((-state-1) >= max) {  // too long, reject
        return -1;
    } else if (alnum[i]&b) {  // keep matching
        match[-state-1] = c;
        return state - 1;
    }
    return -1;
}


// Demo / Test : prints all words 3 to 7 characters in length
#include <stdio.h>

int main(void)
{
    char buf[8];
    int c, state=0, min=3, max=7;
    do {
        c = getchar();
        state = matchn(state, buf, min, max, c==EOF?0:c);
        if (state > 0) {
            buf[state] = '\n';
            fwrite(buf, state+1, 1, stdout);
        }
    } while (c != EOF);
    fflush(stdout);
    return ferror(stdout) || ferror(stdin);
}
