#include "cp1252.c"
#include <stdio.h>

int
main(void)
{
    int fail = 0;

    for (int c = 0; c < 256; c++) {
        long r = cp1252_to_unicode(c);
        int x = unicode_to_cp1252(r);
        if (c != x) {
            printf("FAIL: round trip through Unicode, %02x != %02x\n", c, x);
            fail++;
        }
    }

    for (long r = 0; r <= 0x10ffff; r++) {
        int c = unicode_to_cp1252(r);
        long x = cp1252_to_unicode(c);
        if ((r == 0x1a && c != 0x1a) || (c != 0x1a && x != r)) {
            printf("FAIL: round trip through CP-1252, %04lx != %04lx [%02x]\n",
                   r, x, c);
            fail++;
        }
    }

    for (int c = 0; c < 256; c++) {
        unsigned char buf[4] = {0, 0, 0, 0};
        int ez = cp1252_to_utf8(buf, c);
        unsigned char x;
        int dz = utf8_to_cp1252(&x, buf);
        if (ez != dz || x != c) {
            printf("FAIL: round trip through UTF-8, %02x != %02x "
                   "[%02x %02x %02x]\n", c, x, buf[0], buf[1], buf[2]);
        }
    }

    if (fail) {
        return 1;
    }
    puts("All tests pass");
    return 0;
}
