#include <stdio.h>
#include "siphash.h"

static long test_total = 0;
static long test_fails = 0;

static void
test(struct siphash *s, const unsigned char *buf, int len, uint64_t expect)
{
    if (!len) {
        test_total++;
        test_fails += siphash_final(s) != expect;
    } else {
        for (int i = len - 16 > 1 ? len - 16 : 1; i <= len; i++) {
            struct siphash c = *s;
            siphash_update(&c, buf, i);
            test(&c, buf + i, len - i, expect);
        }
    }
}

static const unsigned char key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const unsigned char input[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};
static const uint64_t expect[64] = {
    0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a,
    0x85676696d7fb7e2d, 0xcf2794e0277187b7, 0x18765564cd99a68d,
    0xcbc9466e58fee3ce, 0xab0200f58b01d137, 0x93f5f5799a932462,
    0x9e0082df0ba9e4b0, 0x7a5dbbc594ddb9f3, 0xf4b32f46226bada7,
    0x751e8fbc860ee5fb, 0x14ea5627c0843d90, 0xf723ca908e7af2ee,
    0xa129ca6149be45e5, 0x3f2acc7f57c29bdb, 0x699ae9f52cbe4794,
    0x4bc1b3f0968dd39c, 0xbb6dc91da77961bd, 0xbed65cf21aa2ee98,
    0xd0f2cbb02e3b67c7, 0x93536795e3a33e88, 0xa80c038ccd5ccec8,
    0xb8ad50c6f649af94, 0xbce192de8a85b8ea, 0x17d835b85bbb15f3,
    0x2f2e6163076bcfad, 0xde4daaaca71dc9a5, 0xa6a2506687956571,
    0xad87a3535c49ef28, 0x32d892fad841c342, 0x7127512f72f27cce,
    0xa7f32346f95978e3, 0x12e0b01abb051238, 0x15e034d40fa197ae,
    0x314dffbe0815a3b4, 0x027990f029623981, 0xcadcd4e59ef40c4d,
    0x9abfd8766a33735c, 0x0e3ea96b5304a7d0, 0xad0c42d6fc585992,
    0x187306c89bc215a9, 0xd4a60abcf3792b95, 0xf935451de4f21df2,
    0xa9538f0419755787, 0xdb9acddff56ca510, 0xd06c98cd5c0975eb,
    0xe612a3cb9ecba951, 0xc766e62cfcadaf96, 0xee64435a9752fe72,
    0xa192d576b245165a, 0x0a8787bf8ecb74b2, 0x81b3e73d20b49b6f,
    0x7fa8220ba3b2ecea, 0x245731c13ca42499, 0xb78dbfaf3a8d83bd,
    0xea1ad565322a1a0b, 0x60e61c23a3795013, 0x6606d7e446282b93,
    0x6ca4ecb15c5f91e1, 0x9f626da15c9625f3, 0xe51b38608ef25f57,
    0x958a324ceb064572,
};

int
main(void)
{
    struct siphash s;
    siphash_init(&s, key);
    for (int i = 0; i < (int)sizeof(input); i++) {
        test(&s, input, i, expect[i]);
    }

    if (test_fails) {
        printf("FAILURE: %ld / %ld tests fail\n", test_fails, test_total);
        return 1;
    } else {
        printf("SUCCESS: All %ld tests pass\n", test_total);
        return 0;
    }
}
