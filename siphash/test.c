#include <stdio.h>
#include "siphash.h"

static int test_total = 0;
static int test_fails = 0;

static void
test(const struct siphash *s, const unsigned char *buf, int len)
{
    if (!len) {
        test_total++;
        test_fails += siphash_final(s) != 0xa129ca6149be45e5;
    } else {
        for (int i = 1; i <= len; i++) {
            struct siphash c = *s;
            siphash_update(&c, buf, i);
            test(&c, buf + i, len - i);
        }
    }
}

int
main(void)
{
    static const unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    static const unsigned char buf[15] = {
        0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    };
    struct siphash s;
    siphash_init(&s, key);
    test(&s, buf, sizeof(buf));

    if (test_fails) {
        printf("FAILURE: %d / %d tests fail\n", test_fails, test_total);
        return 1;
    } else {
        printf("SUCCESS: All %d tests pass\n", test_total);
        return 0;
    }
}
