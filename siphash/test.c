#include <stdio.h>
#include "siphash.h"

static long test_total = 0;
static long test_fails = 0;

static void
test(struct siphash *s, const void *buf, int len, uint64_t expect)
{
    if (!len) {
        test_total++;
        test_fails += siphash_final(s) != expect;
    } else {
        for (int i = len - 16 > 1 ? len - 16 : 1; i <= len; i++) {
            struct siphash c = *s;
            siphash_update(&c, buf, i);
            test(&c, (char *)buf + i, len - i, expect);
        }
    }
}

static void
test128(struct siphash *s, const void *buf, int len, const uint64_t *e)
{
    if (!len) {
        test_total++;
        unsigned char output[16];
        siphash_final128(s, output);
        unsigned char *p = output;
        uint64_t e0 = (uint64_t)p[7] << 56 | (uint64_t)p[6] << 48 |
                      (uint64_t)p[5] << 40 | (uint64_t)p[4] << 32 |
                      (uint64_t)p[3] << 24 | (uint64_t)p[2] << 16 |
                      (uint64_t)p[1] <<  8 | (uint64_t)p[0] <<  0;
        p += 8;
        uint64_t e1 = (uint64_t)p[7] << 56 | (uint64_t)p[6] << 48 |
                      (uint64_t)p[5] << 40 | (uint64_t)p[4] << 32 |
                      (uint64_t)p[3] << 24 | (uint64_t)p[2] << 16 |
                      (uint64_t)p[1] <<  8 | (uint64_t)p[0] <<  0;
        test_fails += (e0 != e[0] || e1 != e[1]);
    } else {
        for (int i = len - 16 > 1 ? len - 16 : 1; i <= len; i++) {
            struct siphash c = *s;
            siphash_update(&c, buf, i);
            test128(&c, (char *)buf + i, len - i, e);
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
static const uint64_t expect128[64][2] = {
    {0xe6a825ba047f81a3, 0x930255c71472f66d},
    {0x44af996bd8c187da, 0x45fc229b11597634},
    {0xc75da4a48d227781, 0xe4ff0af6de8ba3fc},
    {0x4ea967520cb6709c, 0x51ed8529b0b6335f},
    {0xaf8f9c2dc16481f8, 0x7955cd7b7c6e0f7d},
    {0x886f778059876813, 0x27960e69077a5254},
    {0x1386208b33caee14, 0x5ea1d78f30a05e48},
    {0x53c1dbd8beebf1a1, 0x3982f01fa64ab8c0},
    {0x61f55862baa9623b, 0xb49714f364e2830f},
    {0xabbad90a06994426, 0xed716dbb028b7fc4},
    {0x56691478c30d1100, 0xbafbd0f3d34754c9},
    {0x77666b3868c55101, 0x18dce5816fdcb4a2},
    {0x58f35e9066b226d6, 0x25c13285f64d6382},
    {0x108bc0e947e26998, 0xf752b9c44f9329d0},
    {0x9cded766aceffc31, 0x024949e45f48c77e},
    {0x11a8b03399e99354, 0xd9c3cf970fec087e},
    {0xbb54b067caa4e26e, 0x77052385bf1533fd},
    {0x98b88d73e8063d47, 0x4077e47ac466c054},
    {0x8548bf23e4e526a4, 0x23f7aefe81a44d29},
    {0xb0fa65cf31770178, 0xb12e51528920d574},
    {0x7390223f83fc259e, 0xeb3938e8a544933e},
    {0x215a52be5a498e56, 0x121d073ecd14228a},
    {0x9a6bd15245b5294a, 0xae0aff8e52109c46},
    {0xe0f5a9d5dd84d1c9, 0x1c69bf9a9ae28ccf},
    {0xd850bd78ae79b42d, 0xad32618a178a2a88},
    {0x7b445e2d045fce8e, 0x6f8f8dcbeab95150},
    {0xe807c3b3b4530b9c, 0x661f147886e0ae7e},
    {0xe4eaa669af48f2ab, 0x94eb9e122febd3bf},
    {0x884b576816da6406, 0xf4ae587302f335b9},
    {0xe97d33bfc49d4baa, 0xb76a7c463cfdd40c},
    {0xde6baf1f477f5cea, 0x87226d68d4d71a2b},
    {0xfcfa233218b03929, 0x353dc4524fde2317},
    {0x3efcea5eca56397c, 0x68eb4665559d3e36},
    {0x321cf0467107c677, 0xcfffa94e5f9db6b6},
    {0xdf7e84b86c98a637, 0xde549b30f1f02509},
    {0xf9a8a99de6f005a7, 0xc88c3c922e1a2407},
    {0x4648c4291f7dc43d, 0x11674f90ed769e1e},
    {0x1a0efce601bf620d, 0x2b69d3c551473c0d},
    {0x9e667cca8b46038c, 0xb5e7be4b085efde4},
    {0x9c2caf3bb95b8a52, 0xd92bd2d0e5cc7344},
    {0xad5dc9951e306adf, 0xd83b91c6c80cae97},
    {0x397f852c90891180, 0xdbb6705e289135e7},
    {0xbb31c2c96a3417e6, 0x5b0ccacc34ae5036},
    {0xaa21b7ef3734d927, 0x89df5aecdc211840},
    {0x785e9ced9d7d2389, 0x4273cc66b1c9b1d8},
    {0x657d5ebf91806d4a, 0x4cb150a294fa8911},
    {0x89aee75560f9330e, 0x022949cf3d0efc3f},
    {0xd1190b722b431ce6, 0x1b1563dc4bd8c88e},
    {0xcf82f749f5aee5f7, 0x169b2608a6559037},
    {0x4fa5b7d00f038d43, 0x03641a20adf237a8},
    {0xe304bf4feed390a5, 0x3f4286f2270d7e24},
    {0xc493fe72a1c1e25f, 0x38f5f9ae7cd35cb1},
    {0x6eb306bd5c32972c, 0x7c013a8bd03d13b2},
    {0x94ca6b7a2214c892, 0x9ed32a009f65f09f},
    {0x8c32d80b1150e8dc, 0x871d91d64108d5fb},
    {0x1279dac78449f167, 0xda832592b52be348},
    {0xe94ed572cff23819, 0x362a1da96f16947e},
    {0xfe49ed46961e4874, 0x8e6904163024620f},
    {0xd8d6a998dea5fc57, 0x1d8a3d58d0386400},
    {0xbe1cdcef1cdeec9f, 0x595357d9743676d4},
    {0x53f128eb000c04e3, 0x40e772d8cb73ca66},
    {0xfe1d836a9a009776, 0x7a0f6793591ca9cc},
    {0xa067f52123545358, 0xbd5947f0a447d505},
    {0x4a83502f77d15051, 0x7cbd3f979a063e50},
};

int
main(void)
{
    struct siphash s;
    siphash_init(&s, key);
    for (int i = 0; i < (int)sizeof(input); i++) {
        test(&s, input, i, expect[i]);
    }

    siphash_init128(&s, key);
    for (int i = 0; i < (int)sizeof(input); i++) {
        test128(&s, input, i, expect128[i]);
    }

    if (test_fails) {
        printf("FAILURE: %ld / %ld tests fail\n", test_fails, test_total);
        return 1;
    } else {
        printf("SUCCESS: All %ld tests pass\n", test_total);
        return 0;
    }
}
