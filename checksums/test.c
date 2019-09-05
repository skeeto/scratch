/* $ cc -Og -g -fsanitize=address,undefined test.c
 * On x86-64, add -march=x86-64-v2 to test hardware implementation.
 * This is free and unencumbered software released into the public domain.
 */
#include "crc32.h"
#include "crc32c.h"
#include "adler32.h"
#include "crc16x25.h"
#include <stdio.h>

#define COUNTOF(a) (int)(sizeof(a) / sizeof(0[a]))

static const unsigned char test_input[] =
    "The quick brown fox jumps over the lazy dog";

static const unsigned long test_crc32[] = {
    0x00000000, 0xbe047a60, 0xdc6763c5, 0x04082b06, 0x000b625b, 0x09b92d39,
    0xad615b1b, 0x6ca49ec6, 0x74d21c74, 0x5f7e3064, 0xa3ec1434, 0x50a9f758,
    0x09e98fac, 0xd0669508, 0x1268e5b5, 0xc3118c34, 0xc81b2a7c, 0x2fa80ddd,
    0xf7429520, 0xb74574de, 0x88b075e2, 0x31e954ea, 0xb283880c, 0xe8053dcb,
    0x8e5980b4, 0xd78ce11e, 0x13b47ec7, 0x0a1c7029, 0x29dcbf98, 0x1127bd93,
    0x051e1ade, 0x88022e8c, 0x61ec978d, 0x020315ed, 0x3163e78a, 0xe430c69c,
    0x6f5b2d57, 0x1dd72139, 0x3dca2886, 0xff3dca28, 0xdc265a75, 0xb86ee925,
    0x44b329ea,
};

static const unsigned long test_crc32c[] = {
    0x00000000, 0xc4c21e9d, 0x9426ea26, 0x00c29bf3, 0x92fe8395, 0x764592d7,
    0x117bd392, 0x388beccc, 0xae1d513f, 0xc46c03cc, 0xfcca5898, 0xca0dde44,
    0x44f5f0d6, 0x989e0fa4, 0x9266df01, 0x6d3a9ac8, 0x3bf9991e, 0xa907a60a,
    0x06e3d389, 0x537e5cf4, 0x46675bb9, 0x92b82655, 0x725265a9, 0x5618b0ef,
    0x9e908bd2, 0x02c3f57f, 0x5d497653, 0x2f809c46, 0x62b19a7c, 0x3af3fe68,
    0x29fb4ff8, 0x0b5e117a, 0xfe0eb267, 0x0c9061c7, 0x11010661, 0xe17ccce8,
    0x17f083fa, 0x594bf4fe, 0x1748b4c2, 0x79f6c217, 0xb62d88c9, 0x4fa887ac,
    0x82ef2ee6,
};

static const unsigned long test_adler32[] = {
    0x00000001, 0x00550055, 0x011200bd, 0x02340122, 0x03760142, 0x052901b3,
    0x07510228, 0x09e20291, 0x0cd602f4, 0x1035035f, 0x13b4037f, 0x179503e1,
    0x1be80453, 0x20aa04c2, 0x25e30539, 0x2b8a05a7, 0x315105c7, 0x377e062d,
    0x3e1a069c, 0x452e0714, 0x4c620734, 0x5400079e, 0x5c130813, 0x64930880,
    0x6d8308f0, 0x76e60963, 0x80690983, 0x8a5b09f2, 0x94c30a68, 0x9f900acd,
    0xaacf0b3f, 0xb62e0b5f, 0xc2010bd3, 0xce3c0c3b, 0xdadc0ca0, 0xe79c0cc0,
    0xf4c80d2c, 0x02640d8d, 0x106b0e07, 0x1eeb0e80, 0x2d8b0ea0, 0x3c8f0f04,
    0x4c020f73,
};

static const unsigned test_crc16x25[] = {
    0x0000, 0xe4d9, 0x549e, 0xb970, 0xa244, 0x96f4, 0x656f, 0x952b, 0x3ea1,
    0x9910, 0xc162, 0xf0b9, 0x8857, 0x4d3b, 0x785d, 0xf318, 0x4d40, 0xb401,
    0x7ab4, 0xfc62, 0x9192, 0x8b2e, 0x1ca5, 0xba20, 0xa247, 0x877d, 0x799f,
    0x078e, 0x8bb8, 0xfd9b, 0x8a4a, 0x3cae, 0x8993, 0xb9ad, 0xba85, 0x0265,
    0x6dbb, 0x89c2, 0xc932, 0x0c66, 0xd746, 0xf2bf, 0x2607,
};

int
main(void)
{
    int i, j;
    int fail = 0, pass = 0;

    for (i = 0; i < COUNTOF(test_crc32); i++) {
        unsigned long crc = crc32_update(0, test_input, i);
        if (crc != test_crc32[i]) {
            fail++;
            printf("FAIL: crc32%3d, want %08lx, got %08lx\n",
                   i, test_crc32[i], crc);
        } else {
            pass++;
        }

        crc = 0;
        for (j = 0; j < i; j++) {
            crc = crc32_update(crc, test_input + j, 1);
        }
        if (crc != test_crc32[i]) {
            fail++;
            printf("FAIL: crc32%3d (incremental), want %08lx, got %08lx\n",
                   i, test_crc32[i], crc);
        } else {
            pass++;
        }

    }

    for (i = 0; i < COUNTOF(test_crc32); i++) {
        unsigned long crc = crc32c_update(0, test_input, i);
        if (crc != test_crc32c[i]) {
            fail++;
            printf("FAIL: crc32c%3d, want %08lx, got %08lx\n",
                   i, test_crc32c[i], crc);
        } else {
            pass++;
        }


        crc = 0;
        for (j = 0; j < i; j++) {
            crc = crc32c_update(crc, test_input + j, 1);
        }
        if (crc != test_crc32c[i]) {
            fail++;
            printf("FAIL: crc32c%3d (incremental), want %08lx, got %08lx\n",
                   i, test_crc32c[i], crc);
        } else {
            pass++;
        }

    }

    for (i = 0; i < COUNTOF(test_adler32); i++) {
        unsigned long pre, suf;
        unsigned long r = adler32_update(1, test_input, i);
        if (r != test_adler32[i]) {
            fail++;
            printf("FAIL: adler32%3d, want %08lx, got %08lx\n",
                   i, test_adler32[i], r);
        } else {
            pass++;
        }

        r = 1;
        for (j = 0; j < i; j++) {
            r = adler32_update(r, test_input + j, 1);
        }
        if (r != test_adler32[i]) {
            fail++;
            printf("FAIL: adler32%3d (incremental), want %08lx, got %08lx\n",
                   i, test_adler32[i], r);
        } else {
            pass++;
        }

        pre = adler32_update(1, test_input, (i+1)/2);
        suf = adler32_update(1, test_input + (i+1)/2, i/2);
        r = adler32_combine(pre, suf, i/2);
        if (r != test_adler32[i]) {
            fail++;
            printf("FAIL: adler32%3d (combine), want %08lx, got %08lx\n",
                   i, test_adler32[i], r);
        } else {
            pass++;
        }

    }

    for (i = 0; i < COUNTOF(test_crc16x25); i++) {
        unsigned crc = crc16x25_update(0, test_input, i);
        if (crc != test_crc16x25[i]) {
            fail++;
            printf("FAIL: crc16x25%3d, want %04x, got %04x\n",
                   i, test_crc16x25[i], crc);
        } else {
            pass++;
        }

        crc = 0;
        for (j = 0; j < i; j++) {
            crc = crc16x25_update(crc, test_input + j, 1);
        }
        if (crc != test_crc16x25[i]) {
            fail++;
            printf("FAIL: crc16x25%3d (incremental), want %04x, got %04x\n",
                   i, test_crc16x25[i], crc);
        } else {
            pass++;
        }
    }

    if (fail) {
        printf("%d tests failed\n", fail);
        return 1;
    }
    printf("All %d tests passed\n", pass);
    return 0;
}
