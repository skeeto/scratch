// QOI decoder in ~100 lines of 32-bit/64-bit freestanding C
// This is free and unencumbered software released into the public domain.

struct qoi {
    unsigned char *p, *end;
    int width, height, count;
    unsigned error:1, alpha:1, srgb:1, run:6, c, table[64];
};

// Validate the image header and populate the decoder with the image
// metadata (width, height, alpha, srgb). Image dimensions can always be
// multiplied without overflow. If the header is invalid, the error flag
// will be set immediately.
//
// Call the decoder exactly width*height times, or until the error flag
// is set. Alternatively, keep calling until "count" reaches zero, then
// the error flag indicates if the entire decode was successful.
static struct qoi qoiinit(const void *buf, int len)
{
    struct qoi qoi = {0, 0, 0, 0, 0, 1, 0, 0, 0, 0xff000000, {0}};
    if (len < 14) {
        return qoi;
    }

    unsigned char *p = (void *)buf;
    unsigned g = (unsigned)p[ 0]<<24 | p[ 1]<<16 | p[ 2]<< 8 | p[ 3];
    unsigned w = (unsigned)p[ 4]<<24 | p[ 5]<<16 | p[ 6]<< 8 | p[ 7];
    unsigned h = (unsigned)p[ 8]<<24 | p[ 9]<<16 | p[10]<< 8 | p[11];
    if (g!=0x716f6966U || (!w&&h) || (!h&&w) || p[12]-3u>1 || p[13]>1) {
        return qoi;  // invalid header
    }
    if (w>0x7fffffffU || h>0x7fffffffU) {
        return qoi;  // unreasonably huge dimensions
    }
    if ((h && w>0x7fffffffU/h) || (w && h>0x7fffffffU/w)) {
        return qoi;  // multiplying dimensions will overflow
    }

    qoi.p      = p + 14;
    qoi.end    = p + len;
    qoi.width  = w;
    qoi.height = h;
    qoi.count  = w * h;
    qoi.error  = 0;
    qoi.alpha  = p[12]==4;
    qoi.srgb   = p[13]==1;
    return qoi;
}

// Decode the next ABGR pixel. The error flag is sticky, and it is
// permitted to continue "decoding" even when the error field is set.
static unsigned qoinext(struct qoi *q)
{
    if (!q->count || q->error || q->p==q->end) {
        error: q->error=1, q->count=0;
        return 0;
    } else if (q->run) {
        q->run--;
    } else {
        int v = *q->p++;
        unsigned char *p=q->p, r, g, b, a;
        switch (v&0xc0) {
        case 0x00:  // INDEX (spec: "must not" repeat; but real images do)
            q->c = q->table[v&63];
            break;
        case 0x40:  // DIFF
            r=q->c, g=q->c>>8, b=q->c>>16, a=q->c>>24;
            r += (v>>4 & 3) - 2;
            g += (v>>2 & 3) - 2;
            b += (v>>0 & 3) - 2;
            q->c = r | g<<8 | b<<16 | (unsigned)a<<24;
            break;
        case 0x80:  // LUMA
            v = (v&63) - 32;
            if (q->end-p < 1) goto error;
            r=q->c, g=q->c>>8, b=q->c>>16, a=q->c>>24;
            r += v + (*p>>4) - 8;
            g += v;
            b += v + (*p&15) - 8;
            q->c = r | g<<8 | b<<16 | (unsigned)a<<24;
            q->p += 1;
            break;
        case 0xc0:
            switch(v&=63) {
            case 63:  // RGB
                if (q->end-p < 4) goto error;
                q->c = p[0] | p[1]<<8 | p[2]<<16 | (unsigned)p[3]<<24;
                q->p += 4;
                break;
            case 62:  // RGB
                if (q->end-p < 3) goto error;
                r=p[0], g=p[1], b=p[2], a=q->c>>24;
                q->c = r | g<<8 | b<<16 | (unsigned)a<<24;
                q->p += 3;
                break;
            default:  // RUN
                if (q->count < v) goto error;
                q->run = v;
                break;
            }
        }
        r=q->c, g=q->c>>8, b=q->c>>16, a=q->c>>24;
        q->table[(r*3 + g*5 + b*7 + a*11)&63] = q->c;
    }

    if (!--q->count) {
        q->error |= q->end-q->p<8 || q->p[0] || q->p[1] || q->p[2] ||
            q->p[3] || q->p[4] || q->p[5] || q->p[6] || q->p[7]!=1;
    }
    return q->c;
}


#ifdef TEST
// Convert QOI to farbfeld, standard input to standard output
//   $ cc -DTEST -o qoi2ff qoi.c
//   $ ./qoi2ff <example.qoi >example.ff
#include <stdio.h>

int main(void)
{
    #if _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    static char buf[1<<28];
    int len = fread(buf, 1, sizeof(buf), stdin);
    struct qoi qoi = qoiinit(buf, len);

    char header[] = {
        'f', 'a', 'r', 'b', 'f', 'e', 'l', 'd',
        qoi.width  >> 24, qoi.width  >> 16, qoi.width  >> 8, qoi.width,
        qoi.height >> 24, qoi.height >> 16, qoi.height >> 8, qoi.height
    };
    fwrite(header, sizeof(header), 1, stdout);

    while (qoi.count) {
        unsigned c = qoinext(&qoi);
        unsigned char r=c, g=c>>8, b=c>>16, a=c>>24; // TODO: sRGB handling
        unsigned char pixel[] = {
            r, -(r&1), g, -(g&1), b, -(b&1), a, -(a&1)
        };
        fwrite(pixel, sizeof(pixel), 1, stdout);
    }
    fflush(stdout);
    return qoi.error || ferror(stdout) || ferror(stdin);
}
#endif
