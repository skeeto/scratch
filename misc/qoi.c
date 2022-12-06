// QOI decoder in ~100 lines of 32-bit/64-bit freestanding C
// This is free and unencumbered software released into the public domain.

struct qoimeta {
    int width, height;
    unsigned alpha:1, srgb:1;
};

// Validate header and extract image metadata, returning true if the
// header is valid and reasonable. Multiplying the image's dimensions to
// compute the image size will not overflow.
static int qoimeta(struct qoimeta *m, const void *buf, int len)
{
    if (len < 14) {
        return 0;
    }

    const unsigned char *p = buf;
    unsigned g = (unsigned)p[ 0]<<24 | p[ 1]<<16 | p[ 2]<< 8 | p[ 3];
    unsigned w = (unsigned)p[ 4]<<24 | p[ 5]<<16 | p[ 6]<< 8 | p[ 7];
    unsigned h = (unsigned)p[ 8]<<24 | p[ 9]<<16 | p[10]<< 8 | p[11];
    if (g!=0x716f6966U || (!w&&h) || (!h&&w) || p[12]-3u>1 || p[13]>1) {
        return 0;  // invalid header
    }
    if (w>0x7fffffffU || h>0x7fffffffU) {
        return 0;  // unreasonably huge dimensions
    }
    if ((h && w>0x7fffffffU/h) || (w && h>0x7fffffffU/w)) {
        return 0;  // multiplying dimensions will overflow
    }

    m->width  = w;
    m->height = h;
    m->alpha  = p[12] == 4;
    m->srgb   = p[13] == 1;
    return 1;
}

// Decode image into 32-bit array with length width*height, returning
// true on success. Trailing junk is permitted and ignored.
static int qoidecode(unsigned *image, const void *buf, int len)
{
    unsigned char r, g, b, a;
    const unsigned char *p=buf, *e=p+len;
    unsigned c=0xff000000U, table[64] = {0};
    int w = p[ 4]<<24 | p[ 5]<<16 | p[ 6]<<8 | p[ 7];
    int h = p[ 8]<<24 | p[ 9]<<16 | p[10]<<8 | p[11];
    unsigned *end = image + w*h;

    for (p += 14; image<end && p<e;) {
        int v = *p++;
        switch (v&0xc0) {
        case 0x00:  // INDEX (spec: "must not" repeat; but real images do)
            c = *image++ = table[v&63];
            continue;
        case 0x40:  // DIFF
            r=c, g=c>>8, b=c>>16, a=c>>24;
            r += (v>>4 & 3) - 2;
            g += (v>>2 & 3) - 2;
            b += (v>>0 & 3) - 2;
            c = *image++ = r | g<<8 | b<<16 | (unsigned)a<<24;
            break;
        case 0x80:  // LUMA
            v = (v&63) - 32;
            if (e-p < 1) {
                return 0;
            }
            r=c, g=c>>8, b=c>>16, a=c>>24;
            r += (*p >> 4) - 8 + v;
            g +=                 v;
            b += (*p++&15) - 8 + v;
            c = *image++ = r | g<<8 | b<<16 | (unsigned)a<<24;
            break;
        case 0xc0:
            switch(v&=63) {
            case 63:  // RGB
                if (e-p < 4) return 0;
                c = *image++ = p[0] | p[1]<<8 | p[2]<<16 | (unsigned)p[3]<<24;
                p += 4;
                break;
            case 62:  // RGB
                if (e-p < 3) return 0;
                r=p[0], g=p[1], b=p[2], a=c>>24;
                p += 3;
                c = *image++ = r | g<<8 | b<<16 | (unsigned)a<<24;
                break;
            default:  // RUN
                if (end-image < v) return 0;
                do {
                    *image++ = c;
                } while (v--);
                continue;
            }
        }
        r=c, g=c>>8, b=c>>16, a=c>>24;
        table[(r*3 + g*5 + b*7 + a*11)&63] = c;
    }

    return image==end && e-p>=8 &&
        !p[0] && !p[1] && !p[2] && !p[3] && !p[4] && !p[5] && !p[6] && p[7]==1;
}


#ifdef TEST
// Convert QOI to farbfeld, standard input to standard output
//   $ cc -DTEST -o qoi2ff qoi.c
//   $ ./qoi2ff <example.qoi >example.ff
#include <stdio.h>

#define MAX_QOILEN (1<<28)  // 256MiB
#define MAX_PIXELS 100000000

int main(void)
{
    #if _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    static char buf[MAX_QOILEN];
    int len = fread(buf, 1, sizeof(buf), stdin);

    struct qoimeta qoi;
    static unsigned image[MAX_PIXELS];
    if (!qoimeta(&qoi, buf, len) || qoi.width*qoi.height > MAX_PIXELS) {
        return 1;
    }
    if (!qoidecode(image, buf, len)) {
        return 1;
    }

    char header[] = {
        'f', 'a', 'r', 'b', 'f', 'e', 'l', 'd',
        qoi.width  >> 24, qoi.width  >> 16, qoi.width  >> 8, qoi.width,
        qoi.height >> 24, qoi.height >> 16, qoi.height >> 8, qoi.height
    };
    fwrite(header, sizeof(header), 1, stdout);

    for (int i = 0; i < qoi.width*qoi.height; i++) {
        unsigned c = image[i];
        unsigned char r=c, g=c>>8, b=c>>16, a=c>>24;
        unsigned char pixel[] = {
            r, -(r&1), g, -(g&1), b, -(b&1), a, -(a&1)
        };
        fwrite(pixel, sizeof(pixel), 1, stdout);
    }
    fflush(stdout);
    return ferror(stdout) || ferror(stdin);
}
#endif
