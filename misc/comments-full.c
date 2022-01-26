// Converts C++-style comments to C-style comments
// This is free and unencumbered software released into the public domain.
#include <stdio.h>

int main(void)
{
    int state = 0;
    for (int c = getchar(); c != EOF; c = getchar()) {
        switch (state) {
        case 0: switch (c) {       // outside string/comment
                case '"' : state = 1; break;
                case '\'': state = 6; break;
                case '/' : state = 3;
                } break;
        case 1: switch (c) {       // inside string
                case '"' : state = 0; break;
                case '\\': state = 2;
                } break;
        case 2: state = 1; break;  // escape in string
        case 3: switch (c) {       // inside open C/C++ comment token
                default  : state = 0; break;
                case '*' : state = 8; break;
                case '/' : state = 4; c = '*';
                } break;
        case 4: switch (c) {        // inside C++ comment
                case '\\': state = 5; break;
                case '\n': state = 0; fwrite(" */", 3, 1, stdout);
                } break;
        case 5: state = 4; break;  // escape in C++ comment
        case 6: switch (c) {       // inside char literal
                case '\'': state = 0; break;
                case '\\': state = 7;
                } break;
        case 7: state = 6; break;  // escape in char literal
        case 8: switch (c) {       // inside C comment
                case '*' : state = 9;
                } break;
        case 9: switch (c) {       // inside close C comment token
                case '/' : state = 0; break;
                default  : state = 8;
                } break;
        }
        putchar(c);
    }
    return !(!fflush(stdout) && !ferror(stdout) && !ferror(stdin));
}
