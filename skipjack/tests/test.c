#include "../skipjack.h"
#include <stdio.h>
#include <string.h>

static void
print(unsigned char *a)
{
    printf("%02x%02x%02x%02x%02x%02x%02x%02x",
           a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
}

int
main(void)
{
    unsigned char key[] = {
        0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
    };
    unsigned char b[] = {0x33, 0x22, 0x11, 0x00, 0xdd, 0xcc, 0xbb, 0xaa};
    unsigned char e[] = {0x25, 0x87, 0xca, 0xe2, 0x7a, 0x12, 0xd3, 0x00};
    skipjack_encrypt(key, b);
    if (!memcmp(b, e, sizeof(b))) {
        fputs("\x1b[92;1mPASS\x1b[0m: ", stdout);
        print(e);
        fputs(" == ", stdout);
        print(b);
        putchar('\n');
    } else {
        fputs("\x1b[91;1mFAIL\x1b[0m: ", stdout);
        print(e);
        fputs(" == ", stdout);
        print(b);
        putchar('\n');
    }
    return 0;
}
