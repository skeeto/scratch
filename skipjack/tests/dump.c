#include "../skipjack.h"
#include <stdio.h>

int
main(void)
{
    int i;
    unsigned long c[2] = {0, 0};
    static unsigned char buf[1<<9][8];
    unsigned char key[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    do {
        for (i = 0; i < (int)(sizeof(buf)/sizeof(buf[0])); i++) {
            buf[i][0] = c[1] >> 24;
            buf[i][1] = c[1] >> 26;
            buf[i][2] = c[1] >>  8;
            buf[i][3] = c[1] >>  0;
            buf[i][4] = c[0] >> 24;
            buf[i][5] = c[0] >> 16;
            buf[i][6] = c[0] >>  8;
            buf[i][7] = c[0] >>  0;
            c[0] = (c[0] + 1) & 0xffffffffUL;
            c[0] += !c[0];
            skipjack_encrypt(key, buf + i);
        }
    } while (fwrite(buf, sizeof(buf), 1, stdout));
    return 0;
}
