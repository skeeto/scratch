/* Emergency Alert System "two-tone" attention signal
 * Produces an infinite, WAV-formatted 853HZ+960HZ tone on standard output.
 *   $ cc -Os -o twotone twotone.c
 *   $ ./twotone | mpv -
 *   $ ./twotone | ffmpeg -i - -t 3 twotone.mp3
 * This is free and unencumbered software released into the public domain.
 */
#include <stdio.h>

static const unsigned char header[] = {
    0x52, 0x49, 0x46, 0x46, 0xff, 0xff, 0xff, 0xff, 0x57, 0x41, 0x56, 0x45,
    0x66, 0x6d, 0x74, 0x20, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x80, 0x07, 0x00, 0x00, 0x80, 0x07, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
    0x64, 0x61, 0x74, 0x61, 0xff, 0xff, 0xff, 0xff
};
static const unsigned char hz960[] = {0x00, 0xff};
static const unsigned char hz853[] = {
  0xff, 0x08, 0xe1, 0x40, 0x95, 0x96, 0x3f, 0xe2, 0x07, 0xff, 0x08, 0xe0,
  0x41, 0x94, 0x98, 0x3e, 0xe3, 0x07, 0xff, 0x09, 0xdf, 0x42, 0x93, 0x99,
  0x3d, 0xe3, 0x07, 0xff, 0x09, 0xdf, 0x43, 0x91, 0x9a, 0x3c, 0xe4, 0x06,
  0xff, 0x0a, 0xde, 0x45, 0x90, 0x9b, 0x3b, 0xe5, 0x06, 0xff, 0x0a, 0xdd,
  0x46, 0x8f, 0x9c, 0x3a, 0xe6, 0x05, 0xff, 0x0b, 0xdc, 0x47, 0x8e, 0x9e,
  0x39, 0xe6, 0x05, 0xff, 0x0b, 0xdb, 0x48, 0x8c, 0x9f, 0x38, 0xe7, 0x05,
  0xff, 0x0c, 0xda, 0x49, 0x8b, 0xa0, 0x37, 0xe8, 0x04, 0xff, 0x0c, 0xd9,
  0x4a, 0x8a, 0xa1, 0x36, 0xe9, 0x04, 0xfe, 0x0d, 0xd8, 0x4b, 0x89, 0xa3,
  0x35, 0xe9, 0x04, 0xfe, 0x0d, 0xd8, 0x4c, 0x87, 0xa4, 0x34, 0xea, 0x03,
  0xfe, 0x0e, 0xd7, 0x4e, 0x86, 0xa5, 0x33, 0xeb, 0x03, 0xfe, 0x0e, 0xd6,
  0x4f, 0x85, 0xa6, 0x32, 0xeb, 0x03, 0xfe, 0x0f, 0xd5, 0x50, 0x84, 0xa7,
  0x31, 0xec, 0x03, 0xfe, 0x0f, 0xd4, 0x51, 0x82, 0xa8, 0x30, 0xed, 0x02,
  0xfd, 0x10, 0xd3, 0x52, 0x81, 0xaa, 0x2f, 0xed, 0x02, 0xfd, 0x11, 0xd2,
  0x53, 0x80, 0xab, 0x2e, 0xee, 0x02, 0xfd, 0x11, 0xd1, 0x55, 0x7f, 0xac,
  0x2d, 0xef, 0x02, 0xfd, 0x12, 0xd0, 0x56, 0x7d, 0xad, 0x2c, 0xef, 0x02,
  0xfd, 0x13, 0xcf, 0x57, 0x7c, 0xae, 0x2b, 0xf0, 0x01, 0xfc, 0x13, 0xce,
  0x58, 0x7b, 0xb0, 0x2a, 0xf0, 0x01, 0xfc, 0x14, 0xcd, 0x59, 0x7a, 0xb1,
  0x29, 0xf1, 0x01, 0xfc, 0x15, 0xcc, 0x5a, 0x78, 0xb2, 0x28, 0xf1, 0x01,
  0xfb, 0x15, 0xcb, 0x5c, 0x77, 0xb3, 0x27, 0xf2, 0x01, 0xfb, 0x16, 0xca,
  0x5d, 0x76, 0xb4, 0x26, 0xf3, 0x01, 0xfb, 0x17, 0xc9, 0x5e, 0x75, 0xb5,
  0x25, 0xf3, 0x00, 0xfb, 0x17, 0xc8, 0x5f, 0x73, 0xb6, 0x24, 0xf4, 0x00,
  0xfa, 0x18, 0xc7, 0x61, 0x72, 0xb8, 0x24, 0xf4, 0x00, 0xfa, 0x19, 0xc6,
  0x62, 0x71, 0xb9, 0x23, 0xf5, 0x00, 0xfa, 0x1a, 0xc5, 0x63, 0x70, 0xba,
  0x22, 0xf5, 0x00, 0xf9, 0x1a, 0xc4, 0x64, 0x6e, 0xbb, 0x21, 0xf6, 0x00,
  0xf9, 0x1b, 0xc3, 0x65, 0x6d, 0xbc, 0x20, 0xf6, 0x00, 0xf8, 0x1c, 0xc2,
  0x67, 0x6c, 0xbd, 0x1f, 0xf7, 0x00, 0xf8, 0x1d, 0xc1, 0x68, 0x6b, 0xbe,
  0x1f, 0xf7, 0x00, 0xf8, 0x1d, 0xc0, 0x69, 0x69, 0xbf, 0x1e, 0xf7, 0x00,
  0xf7, 0x1e, 0xbf, 0x6a, 0x68, 0xc0, 0x1d, 0xf8, 0x00, 0xf7, 0x1f, 0xbd,
  0x6c, 0x67, 0xc1, 0x1c, 0xf8, 0x00, 0xf6, 0x20, 0xbc, 0x6d, 0x66, 0xc2,
  0x1b, 0xf9, 0x00, 0xf6, 0x21, 0xbb, 0x6e, 0x65, 0xc4, 0x1b, 0xf9, 0x00,
  0xf5, 0x22, 0xba, 0x6f, 0x63, 0xc5, 0x1a, 0xf9, 0x00, 0xf5, 0x22, 0xb9,
  0x71, 0x62, 0xc6, 0x19, 0xfa, 0x00, 0xf4, 0x23, 0xb8, 0x72, 0x61, 0xc7,
  0x18, 0xfa, 0x00, 0xf4, 0x24, 0xb7, 0x73, 0x60, 0xc8, 0x18, 0xfa, 0x00,
  0xf3, 0x25, 0xb6, 0x74, 0x5f, 0xc9, 0x17, 0xfb, 0x01, 0xf3, 0x26, 0xb4,
  0x75, 0x5d, 0xca, 0x16, 0xfb, 0x01, 0xf2, 0x27, 0xb3, 0x77, 0x5c, 0xcb,
  0x15, 0xfb, 0x01, 0xf2, 0x28, 0xb2, 0x78, 0x5b, 0xcc, 0x15, 0xfc, 0x01,
  0xf1, 0x29, 0xb1, 0x79, 0x5a, 0xcd, 0x14, 0xfc, 0x01, 0xf1, 0x2a, 0xb0,
  0x7a, 0x58, 0xce, 0x13, 0xfc, 0x01, 0xf0, 0x2a, 0xaf, 0x7c, 0x57, 0xcf,
  0x13, 0xfc, 0x01, 0xef, 0x2b, 0xae, 0x7d, 0x56, 0xd0, 0x12, 0xfd, 0x02,
  0xef, 0x2c, 0xac, 0x7e, 0x55, 0xd1, 0x12, 0xfd, 0x02, 0xee, 0x2d, 0xab,
  0x80, 0x54, 0xd2, 0x11, 0xfd, 0x02, 0xed, 0x2e, 0xaa, 0x81, 0x53, 0xd3,
  0x10, 0xfd, 0x02, 0xed, 0x2f, 0xa9, 0x82, 0x51, 0xd4, 0x10, 0xfe, 0x03,
  0xec, 0x30, 0xa8, 0x83, 0x50, 0xd5, 0x0f, 0xfe, 0x03, 0xec, 0x31, 0xa7,
  0x85, 0x4f, 0xd5, 0x0e, 0xfe, 0x03, 0xeb, 0x32, 0xa5, 0x86, 0x4e, 0xd6,
  0x0e, 0xfe, 0x03, 0xea, 0x33, 0xa4, 0x87, 0x4d, 0xd7, 0x0d, 0xfe, 0x04,
  0xea, 0x34, 0xa3, 0x88, 0x4c, 0xd8, 0x0d, 0xfe, 0x04, 0xe9, 0x35, 0xa2,
  0x8a, 0x4b, 0xd9, 0x0c, 0xfe, 0x04, 0xe8, 0x36, 0xa0, 0x8b, 0x49, 0xda,
  0x0c, 0xff, 0x05, 0xe7, 0x37, 0x9f, 0x8c, 0x48, 0xdb, 0x0b, 0xff, 0x05,
  0xe7, 0x38, 0x9e, 0x8d, 0x47, 0xdc, 0x0b, 0xff, 0x05, 0xe6, 0x39, 0x9d,
  0x8e, 0x46, 0xdd, 0x0a, 0xff, 0x06, 0xe5, 0x3a, 0x9c, 0x90, 0x45, 0xdd,
  0x0a, 0xff, 0x06, 0xe4, 0x3b, 0x9a, 0x91, 0x44, 0xde, 0x09, 0xff, 0x06,
  0xe4, 0x3d, 0x99, 0x92, 0x43, 0xdf, 0x09, 0xff, 0x07, 0xe3, 0x3e, 0x98,
  0x93, 0x42, 0xe0, 0x08, 0xff, 0x07, 0xe2, 0x3f, 0x97, 0x95, 0x40, 0xe1,
  0x08
};

int main(void)
{
    if (fwrite(header, sizeof(header), 1, stdout)) {
        int i = 0, j = 0;
        for (; putchar((hz853[i] + hz960[j])/2) != EOF;
             i = (i + 1)%sizeof(hz853),
             j = (j + 1)%sizeof(hz960));
    }
    return 1;
}