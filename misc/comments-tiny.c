// Converts C++-style comments to C-style comments
// This is free and unencumbered software released into the public domain.
#include <stdio.h>
int main(void)
{
    static const signed char t[][256] = {
        [0] = {[0x22] = +1, [0x27] = +6, [0x2f] = +3}, [8] = {[0x2a] = +1},
        [1] = {[0x22] = -1, [0x5c] = +1}, [3] = {[0x2f] = +4, [0x2a] = +8},
        [4] = {[0x0a] = -4, [0x5c] = +1}, [6] = {[0x27] = -6, [0x5c] = +1},
        [9] = {[0x2f] = -8}, {0, 1, 1, 0, 4, 4, 6, 6, 8, 8}
    };
    for (int s = 0, c = getchar(); c != EOF; c = getchar()) {
        int n = t[s][c] + t[10][s];
        switch (s*16 + n) {
        case 0x34: c = 0x2a; break;
        case 0x40: fwrite("\x20\x2a\x2f", 3, 1, stdout);
        }
        putchar(c);
        s = n;
    }
    return !(!ferror(stdin) && !fflush(stdout) && !ferror(stdout));
}
