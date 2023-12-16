// Small, in-place URL decoder state machine
// This is free and unencumbered software released into the public domain.

// Decode a URL in place, returning the new length.
int urldecode(char *buf, int len)
{
    static const char values[256] = {
        ['0']= 1, ['1']= 2, ['2']= 3, ['3']= 4, ['4']= 5,
        ['5']= 6, ['6']= 7, ['7']= 8, ['8']= 9, ['9']=10,
        ['A']=11, ['B']=12, ['C']=13, ['D']=14, ['E']=15, ['F']=16,
        ['a']=11, ['b']=12, ['c']=13, ['d']=14, ['e']=15, ['f']=16,
    };

    int out   = 0;
    int state = 0;
    int accum = 0;
    for (int i = 0; i < len; i++) {
        char c = buf[i];
        int  v = values[c&255] - 1;
        switch (state) {
        case 0: state = c == '%';
                break;
        case 1: switch (v) {
                case -1: state = c == '%';
                         break;
                default: state = 2;
                         accum = v << 4;
                } break;
        case 2: switch (v) {
                case -1: state = c == '%';
                         break;
                default: state = 0;
                         out -= 2;  // rewind
                         c = (char)(accum | v);
                } break;
        }
        buf[out++] = c;
    }
    return out;
}


#ifdef DEMO
#include <stdio.h>

int main(void)
{
    char url[] = "Let%27s%20make%20%cf%80!";
    int len = urldecode(url, sizeof(url)-1);
    printf("%.*s\n", len, url);
}
#endif
