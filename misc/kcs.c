/* Kansas City Standard encoder
 * Encodes standard input to an 8-bit PCM 22,050 Hz WAV on standard output.
 * This is free and unencumbered software released into the public domain.
 */
#include <stdio.h>

#ifndef BAUD
#  define BAUD 300    // 300, 600, or 1200
#endif
#ifndef STOPBITS
#  define STOPBITS 2  // 1 or 2
#endif

static const short lengths[] = {19, 18, 18, 18, 18, 18, 19, 19};
static const unsigned char samples[2][8][19] = {
    {
        {0x7f, 0xaa, 0xd0, 0xec, 0xfc, 0xfd, 0xf0, 0xd6, 0xb1, 0x87,
         0x5c, 0x35, 0x16, 0x04, 0x00, 0x0a, 0x22, 0x45, 0x6f},
        {0xa5, 0xcb, 0xe9, 0xfb, 0xfe, 0xf2, 0xda, 0xb6, 0x8d, 0x61,
         0x39, 0x1a, 0x06, 0x00, 0x08, 0x1f, 0x40, 0x69},
        {0x9f, 0xc7, 0xe6, 0xf9, 0xfe, 0xf5, 0xdd, 0xbb, 0x92, 0x67,
         0x3e, 0x1d, 0x07, 0x00, 0x06, 0x1b, 0x3c, 0x64},
        {0x9a, 0xc2, 0xe3, 0xf8, 0xfe, 0xf7, 0xe1, 0xc0, 0x97, 0x6c,
         0x43, 0x21, 0x09, 0x00, 0x05, 0x18, 0x37, 0x5f},
        {0x95, 0xbe, 0xdf, 0xf6, 0xfe, 0xf8, 0xe4, 0xc5, 0x9d, 0x71,
         0x48, 0x24, 0x0c, 0x00, 0x03, 0x15, 0x33, 0x59},
        {0x8f, 0xb9, 0xdc, 0xf4, 0xfe, 0xfa, 0xe8, 0xc9, 0xa2, 0x77,
         0x4d, 0x28, 0x0e, 0x01, 0x02, 0x12, 0x2e, 0x54},
        {0x8a, 0xb4, 0xd8, 0xf1, 0xfe, 0xfb, 0xeb, 0xcd, 0xa7, 0x7c,
         0x52, 0x2c, 0x11, 0x02, 0x01, 0x0f, 0x2a, 0x4f, 0x7a},
        {0x84, 0xaf, 0xd4, 0xef, 0xfd, 0xfc, 0xed, 0xd2, 0xac, 0x82,
         0x57, 0x31, 0x13, 0x03, 0x00, 0x0d, 0x26, 0x4a, 0x74}
    }, {
        {0x7f, 0xd0, 0xfc, 0xf0, 0xb1, 0x5c, 0x16, 0x00, 0x22, 0x6f,
         0xc2, 0xf8, 0xf7, 0xc0, 0x6c, 0x21, 0x00, 0x18, 0x5f},
        {0xc7, 0xf9, 0xf5, 0xbb, 0x67, 0x1d, 0x00, 0x1b, 0x64, 0xb9,
         0xf4, 0xfa, 0xc9, 0x77, 0x28, 0x01, 0x12, 0x54},
        {0xbe, 0xf6, 0xf8, 0xc5, 0x71, 0x24, 0x00, 0x15, 0x59, 0xaf,
         0xef, 0xfc, 0xd2, 0x82, 0x31, 0x03, 0x0d, 0x4a},
        {0xb4, 0xf1, 0xfb, 0xcd, 0x7c, 0x2c, 0x02, 0x0f, 0x4f, 0xa5,
         0xe9, 0xfe, 0xda, 0x8d, 0x39, 0x06, 0x08, 0x40},
        {0xaa, 0xec, 0xfd, 0xd6, 0x87, 0x35, 0x04, 0x0a, 0x45, 0x9a,
         0xe3, 0xfe, 0xe1, 0x97, 0x43, 0x09, 0x05, 0x37},
        {0x9f, 0xe6, 0xfe, 0xdd, 0x92, 0x3e, 0x07, 0x06, 0x3c, 0x8f,
         0xdc, 0xfe, 0xe8, 0xa2, 0x4d, 0x0e, 0x02, 0x2e},
        {0x95, 0xdf, 0xfe, 0xe4, 0x9d, 0x48, 0x0c, 0x03, 0x33, 0x84,
         0xd4, 0xfd, 0xed, 0xac, 0x57, 0x13, 0x00, 0x26, 0x74},
        {0x8a, 0xd8, 0xfe, 0xeb, 0xa7, 0x52, 0x11, 0x01, 0x2a, 0x7a,
         0xcb, 0xfb, 0xf2, 0xb6, 0x61, 0x1a, 0x00, 0x1f, 0x69}
    }
};
static const unsigned char header[] = {
    0x52, 0x49, 0x46, 0x46, 0xff, 0xff, 0xff, 0xff, 0x57, 0x41, 0x56, 0x45,
    0x66, 0x6d, 0x74, 0x20, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x22, 0x56, 0x00, 0x00, 0x22, 0x56, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
    0x64, 0x61, 0x74, 0x61, 0xff, 0xff, 0xff, 0xff
};
static const unsigned char blank[16];

static void
bit(int b)
{
    static int phase = 0;
    for (int i = 0; i < 1200/BAUD; i++) {
        fwrite(samples[b][phase], lengths[phase], 1, stdout);
        phase = (phase + 3) & 7;
    }
}

int
main(void)
{
    #ifdef _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    fwrite(header, sizeof(header), 1, stdout);
    fwrite(blank, sizeof(blank), 1, stdout);
    for (int c = getchar(); c != EOF; c = getchar()) {
        bit(0);
        for (int i = 0; i < 8; i++) {
            bit(c>>i & 1);
        }
        for (int i = 0; i < STOPBITS; i++) {
            bit(1);
        }
    }
    fwrite(blank, sizeof(blank), 1, stdout);
    fflush(stdout);
    return ferror(stdout);
}
