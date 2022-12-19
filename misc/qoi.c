// QOI en/decoder each in ~100 lines of 32-/64-bit freestanding C
// This is free and unencumbered software released into the public domain.

struct qoidecoder {
    int width, height, count, alpha, srgb, error;
    unsigned char *p, *end;  // internal
    int last, run;           // internal
    unsigned c, table[64];   // internal
};

// Validate the image header and populate a decoder with the image
// metadata (width, height, alpha, srgb). Image dimensions can always be
// multiplied without overflow. If the header is invalid, the error flag
// will be set immediately.
//
// Call the decoder exactly width*height times, or until the error flag
// is set. Alternatively, call until "count" reaches zero, then the
// error flag indicates if the entire decode was successful.
static struct qoidecoder qoidecoder(const void *buf, int len)
{
    struct qoidecoder q = {0, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0xff000000, {0}};
    if (len < 14) {
        return q;
    }

    unsigned char *p = (void *)buf;
    unsigned g = (unsigned)p[ 0]<<24 | p[ 1]<<16 | p[ 2]<< 8 | p[ 3];
    unsigned w = (unsigned)p[ 4]<<24 | p[ 5]<<16 | p[ 6]<< 8 | p[ 7];
    unsigned h = (unsigned)p[ 8]<<24 | p[ 9]<<16 | p[10]<< 8 | p[11];
    if (g!=0x716f6966U || (!w&&h) || (!h&&w) || p[12]-3u>1 || p[13]>1) {
        return q;  // invalid header
    }
    if (h && w>0x7fffffffU/h) {
        return q;  // multiplying dimensions will overflow
    }

    q.p      = p + 14;
    q.end    = p + len;
    q.width  = w;
    q.height = h;
    q.count  = w * h;
    q.error  = 0;
    q.alpha  = p[12]==4;
    q.srgb   = p[13]==1;
    return q;
}

// Decode the next ABGR pixel. The error flag is sticky, and it is
// permitted to continue "decoding" even when the error flag is set.
static unsigned qoidecode(struct qoidecoder *q)
{
    if (!q->count || q->error || q->p==q->end) {
        error: q->error=1, q->count=0;
        return 0;
    } else if (q->run) {
        q->run--;
    } else {
        int n, v=*q->p++;
        unsigned char *p=q->p, r, g, b, a;
        switch (v&0xc0) {
        case 0x00:  // INDEX
            if (q->last == v) goto error;
            q->c = q->table[v];
            goto skiptable;
        case 0x40:  // DIFF
            r=q->c, g=q->c>>8, b=q->c>>16, a=q->c>>24;
            r += (v>>4 & 3) - 2;
            g += (v>>2 & 3) - 2;
            b += (v>>0 & 3) - 2;
            q->c = r | g<<8 | b<<16 | (unsigned)a<<24;
            break;
        case 0x80:  // LUMA
            n = v - (0x80 + 32);
            if (q->end-p < 1) goto error;
            r=q->c, g=q->c>>8, b=q->c>>16, a=q->c>>24;
            r += n + (*p>>4) - 8;
            g += n;
            b += n + (*p&15) - 8;
            q->c = r | g<<8 | b<<16 | (unsigned)a<<24;
            q->p += 1;
            break;
        case 0xc0:
            switch ((n = v&63)) {
            case 63:  // RGBA
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
                if (q->count < n) goto error;
                q->run = n;
                goto skiptable;
            }
        }
        r=q->c, g=q->c>>8, b=q->c>>16, a=q->c>>24;
        q->table[(r*3 + g*5 + b*7 + a*11)&63] = q->c;
        skiptable: q->last = v;
    }

    if (!--q->count) {
        q->error |= q->end-q->p<8 || q->p[0] || q->p[1] || q->p[2] ||
            q->p[3] || q->p[4] || q->p[5] || q->p[6] || q->p[7]!=1;
    }
    return q->c;
}


#define QOIHDRLEN 14

struct qoiencoder {
    int run;
    unsigned c, table[64];
};

// Initialize an encoder and write a 14-byte (QOIHDRLEN) header into the
// buffer. The flags are an optional "mode string" with 'a' if the image
// has an alpha channel, and 's' if the image is sRGB colorspace. Flags
// do not affect the encoding, only the header.
static struct qoiencoder qoiencoder(void *buf, int w, int h, const char *flags)
{
    unsigned char *p = buf;
    struct qoiencoder q = {0, 0xff000000, {0}};
    p[ 0] =   'q'; p[ 1] =   'o'; p[ 2] =  'i'; p[ 3] =  'f';
    p[ 4] = w>>24; p[ 5] = w>>16; p[ 6] = w>>8; p[ 7] = w>>0;
    p[ 8] = h>>24; p[ 9] = h>>16; p[10] = h>>8; p[11] = h>>0;
    p[12] = 3;  // channels
    p[13] = 0;  // srgb
    for (flags = flags?flags:"";; flags++) {
        switch (*flags) {
        case 'a': p[12] = 4; break;
        case 's': p[13] = 1; break;
        case  0 : return q;
        }
    }
}

// Encode the next ABGR pixel into the buffer, returning the number of
// bytes written (0..6). The buffer must be at least 6 bytes in length.
static int qoiencode(struct qoiencoder *q, void *buf, unsigned c)
{
    unsigned char *p = buf;
    if (q->c == c) {
        if (++q->run == 62) {
            q->run = 0;
            *p++ = 0xc0 | 61;
        }
        return p - (unsigned char *)buf;
    } else if (q->run) {
        *p++ = 0xc0 | (q->run - 1);
        q->run = 0;
    }

    unsigned char r=c, g=c>>8, b=c>>16, a=c>>24;
    int i = (r*3 + g*5 + b*7 + a*11)&63;
    if (q->table[i] == c) {
        q->c = c;
        *p++ = i;
        return p - (unsigned char *)buf;
    }
    q->table[i] = c;

    unsigned char R=q->c, G=q->c>>8, B=q->c>>16, A=q->c>>24;
    int dr=r-R, dg=g-G, db=b-B;
    q->c = c;
    if (a==A && dr+2u<4 && dg+2u<4 && db+2u<4) {
        *p++ = 0x40 | (dr+2)<<4 | (dg+2)<<2 | (db+2);
    } else if (a==A && dg+32u<64 && dr-dg+8u<16 && db-dg+8u<16) {
        *p++ = 0x80 | (dg+32);
        *p++ = (dr-dg+8)<<4 | (db-dg+8);
    } else if (a==A) {
        *p++ = 0xfe; *p++ = r; *p++ = g; *p++ = b;
    } else {
        *p++ = 0xff; *p++ = r; *p++ = g; *p++ = b; *p++ = a;
    }
    return p - (unsigned char *)buf;
}

// Flush any remaining encoder state and then write the end-of-stream
// indicator, returning the number of bytes written (8..9). The buffer
// length must be at least 9 bytes.
static int qoifinish(struct qoiencoder *q, void *buf)
{
    unsigned char *p = buf;
    if (q->run) {
        *p++ = 0xc0 | (q->run - 1);
    }
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 1;
    return p - (unsigned char *)buf;
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
    struct qoidecoder dec = qoidecoder(buf, len);

    #if 1
    char header[] = {
        'f', 'a', 'r', 'b', 'f', 'e', 'l', 'd',
        dec.width  >> 24, dec.width  >> 16, dec.width  >> 8, dec.width,
        dec.height >> 24, dec.height >> 16, dec.height >> 8, dec.height
    };
    fwrite(header, sizeof(header), 1, stdout);

    while (dec.count) {
        unsigned c = qoidecode(&dec);
        unsigned char r=c, g=c>>8, b=c>>16, a=c>>24; // TODO: sRGB handling
        unsigned char pixel[] = {
            r, -(r&1), g, -(g&1), b, -(b&1), a, -(a&1)
        };
        fwrite(pixel, sizeof(pixel), 1, stdout);
    }
    fflush(stdout);
    return dec.error || ferror(stdout) || ferror(stdin);

    #else
    // Re-encode to QOI
    char out[QOIHDRLEN];
    struct qoiencoder enc = qoiencoder(out, dec.width, dec.height, 0);
    fwrite(out, QOIHDRLEN, 1, stdout);
    while (dec.count) {
        fwrite(out, qoiencode(&enc, out, qoidecode(&dec)), 1, stdout);
    }
    fwrite(out, qoifinish(&enc, out), 1, stdout);
    fflush(stdout);
    return dec.error || ferror(stdout) || ferror(stdin);
    #endif
}
#endif
