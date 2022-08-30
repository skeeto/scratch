// Netpbm to BMP converter
//   $ cc -O -o pbm2bmp pbm2bmp.c
//   $ ./pbm2bmp <input.ppm >output.bmp
// Supports P2, P3, P5, and P6 at depth 255, including comments
// This is free and unencumbered software released into the public domain.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static uint32_t
bmp_size(int32_t width, int32_t height)
{
    int32_t pad = ((width % 4) * -3UL) & 3;  // overflow-safe
    if (width < 1 || height < 1) {
        return 0;  // illegal size
    } else if (width > ((0x7fffffff - 14 - 40) / height - pad) / 3) {
        return 0;  // overflow
    } else {
        return height * (width*3 + pad) + 14 + 40;
    }
}

static void
bmp_init(void *buf, int32_t width, int32_t height)
{
    int pad;
    uint32_t size;
    uint32_t uw = width;
    uint32_t uh = -height;
    uint8_t *p = (uint8_t *)buf;

    // bfType
    *p++ = 0x42; *p++ = 0x4D;

    // bfSize
    pad = (uw * -3) & 3;
    size = height*(uw*3 + pad) + 14 + 40;
    *p++ = size >>  0; *p++ = size >>  8;
    *p++ = size >> 16; *p++ = size >> 24;

    // bfReserved1 + bfReserved2
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00;

    // bfOffBits
    *p++ = 0x36; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00;

    // biSize
    *p++ = 0x28; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00;

    // biWidth
    *p++ = uw >>  0; *p++ = uw >>  8;
    *p++ = uw >> 16; *p++ = uw >> 24;

    // biHeight
    *p++ = uh >>  0; *p++ = uh >>  8;
    *p++ = uh >> 16; *p++ = uh >> 24;

    // biPlanes
    *p++ = 0x01; *p++ = 0x00;

    // biBitCount
    *p++ = 0x18; *p++ = 0x00;

    // biCompression
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00;

    // biSizeImage
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00;

    // biXPelsPerMeter
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00;

    // biYPelsPerMeter
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00;

    // biClrUsed
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00;

    // biClrImportant
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p   = 0x00;
}

static void
bmp_set(void *buf, int32_t x, int32_t y, int32_t color)
{
    uint8_t *p, *hdr = (uint8_t *)buf;
    uint32_t width = (uint32_t)hdr[18] <<  0 | (uint32_t)hdr[19] <<  8 |
                     (uint32_t)hdr[20] << 16 | (uint32_t)hdr[21] << 24;
    int pad = (width * -3UL) & 3;
    p = hdr + 14 + 40 + y * (width*3 + pad) + x*3;
    p[0]  = color >>  0;
    p[1]  = color >>  8;
    p[2]  = color >> 16;
}

struct netpbm {
    int32_t dims[3];
    int type;
};

// Input a byte into the Netpbm parser state machine, updating the width
// / height / depth array and returning the next state. The initial
// state is zero. A negative return is not a state, but an error:
// PGM_OVERFLOW, PGM_INVALID. The accept state is PGM_DONE, and no
// further input will be accepted. Dimensions are restricted to the
// given maximum: use something reasonable, not LONG_MAX. Fields may be
// left uninitialized on error.
//
// This parser supports arbitrary whitespace and comments.
static int
netpbm_parse(int state, int c, struct netpbm *pbm, int32_t max)
{
    #define PGM_OVERFLOW  -2
    #define PGM_INVALID   -1
    #define PGM_DONE      +5
    switch (state) {
    default: return PGM_INVALID;
    case  0: switch (c) {
             default : return PGM_INVALID;
             case 'P': return 1;
             }
    case  1: switch (c) {
             default : return PGM_INVALID;
             case '2':
             case '3':
             case '5':
             case '6': pbm->type = c - '0';
                       return 2;
             }
    case  2:
    case  3:
    case  4: switch (c) {  // between fields
             default : return 0;
             case '0': case '1': case '2': case '3': case '4':
             case '5': case '6': case '7': case '8': case '9':
                 pbm->dims[state-2] = c - '0';
                 return state + 4;
             case ' ': case '\n': case '\r': case '\t':
                 return state;
             case '#':
                 return state + 7;
             }
    case  6:
    case  7:
    case  8: switch (c) {  // dimensions
             default : return PGM_INVALID;
             case ' ': case '\n': case '\r': case '\t':
                 return state - 3;  // possibly PGM_DONE
             case '#':
                 return state + 4;
             case '0': case '1': case '2': case '3': case '4':
             case '5': case '6': case '7': case '8': case '9':
                 pbm->dims[state-6] = pbm->dims[state-6]*10 + c - '0';
                 if (pbm->dims[state-6] > max) return PGM_OVERFLOW;
                 return state;
             }
    case  9:
    case 10:
    case 11: switch (c) {  // comments
             default  : return state;
             case '\n': return state - 7;
             }
    }
}

// Decode an ASCII byte value from standard input. Return -1 on error.
static int
asciibyte(void)
{
    for (int n = 0, b = 0;;) {
        int c = getchar();
        switch (c) {
        default:
            return -1;
        case EOF:
            return n ? b : -1;
        case '\t': case ' ' : case '\r': case '\n':
            if (n) {
                return b;
            }
            continue;
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            b = b*10 + c - '0';
            if (b > 255 || ++n > 3) {
                return -1;
            }
        }
    }
}

int
main(int argc, char **argv)
{
    #if _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    (void)argv;
    if (argc > 1) {
        fprintf(stderr, "usage: pbm2bmp <PPM >BMP\n");
        return 1;
    }

    struct netpbm pbm = {{0, 0, 0}, 0};
    for (int state = 0, done = 0; !done;) {
        int c = getchar();
        if (c == EOF) {
            fprintf(stderr, "pbm2bmp: premature end of input\n");
            return 1;
        }
        state = netpbm_parse(state, c, &pbm, 1000000);
        switch (state) {
        case PGM_OVERFLOW:
            fprintf(stderr, "pbm2bmp: dimensions too large\n");
            return 1;
        case PGM_INVALID:
            fprintf(stderr, "pbm2bmp: invalid input\n");
            return 1;
        case PGM_DONE:
            switch (pbm.dims[2]) {
            default: fprintf(stderr, "pbm2bmp: unsupported depth\n");
                     return 1;
            case 255: break;
            }
            done = 1;
        }
    }

    int error = 0;
    int32_t w = pbm.dims[0], h = pbm.dims[1];
    size_t size = bmp_size(w, h);
    void *bmp = malloc(size);
    if (!bmp) {
        fprintf(stderr, "pbm2bmp: out of memory\n");
        return 1;
    }
    bmp_init(bmp, w, h);

    switch (pbm.type) {
    default: fprintf(stderr, "pbm2bmp: unsupported format\n");
             return 1;

    case 2:
        for (int32_t y = 0; y < h; y++) {
            for (int32_t x = 0; x < w; x++) {
                int c = asciibyte();
                if (c < 0) {
                    error = 1;
                    break;
                }
                c &= 0xff;
                bmp_set(bmp, x, y, c<<16 | c<<8 | c);
            }
        }
        break;

    case 3:
        for (int32_t y = 0; y < h; y++) {
            for (int32_t x = 0; x < w; x++) {
                int32_t r = asciibyte();
                int32_t g = asciibyte();
                int32_t b = asciibyte();
                if (r < 0 || g < 0 || b < 0) {
                    error = 1;
                    break;
                }
                r &= 0xff; g &= 0xff; b &= 0xff;
                bmp_set(bmp, x, y, r<<16 | g<<8 | b);
            }
        }
        break;

    case 5:
        for (int32_t y = 0; y < h; y++) {
            for (int32_t x = 0; x < w; x++) {
                int32_t c = getchar();
                if (c == EOF) {
                    error = 1;
                    break;
                }
                c &= 0xff;
                bmp_set(bmp, x, y, c<<16 | c<<8 | c);
            }
        }
        break;

    case 6:
        for (int32_t y = 0; y < h; y++) {
            for (int32_t x = 0; x < w; x++) {
                uint8_t p[3];
                if (!fread(p, 3, 1, stdin)) {
                    error = 1;
                    break;
                }
                bmp_set(bmp, x, y, p[0]<<16 | p[1]<<8 | p[2]);
            }
        }
        break;
    }

    if (error) {
        // TODO: better diagnostic
        fprintf(stderr, "pbm2bmp: invalid input\n");
        return 1;
    }

    fwrite(bmp, size, 1, stdout);
    fflush(stdout);
    if (ferror(stdout)) {
        fprintf(stderr, "pbm2bmp: output error\n");
        return 1;
    }
    return 0;
}
