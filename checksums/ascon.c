// Ascon-Hash cryptographic hash function
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>

#define ASCON_DIGEST_LENGTH 32

// Ascon-Hash state: initialize to zero.
struct ascon {
    uint64_t x[5];
    uint8_t buf[8];
    int len;
};

static void ascon_push(struct ascon *, const void *, size_t);
static void ascon_final(struct ascon *, void *);


// Implementation

static void ascon_init(struct ascon *c)
{
    c->x[0] = 0xee9398aadb67f03d;
    c->x[1] = 0x8bb21831c60f1002;
    c->x[2] = 0xb48a92db98d5da62;
    c->x[3] = 0x43189921b8f8e3e8;
    c->x[4] = 0x348fa5c9d525e140;
    c->len = 8;
}

static void ascon_permute(struct ascon *c)
{
    uint64_t *x = c->x;
    for (int i = 0; i < 12; i++) {
        static const uint8_t r[12] = {
            0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b
        };
        x[2] ^= r[i];

        uint64_t t[5];
        x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1];
        t[0]  = x[0]; t[1]  = x[1]; t[2]  = x[2];
        t[3]  = x[3]; t[4]  = x[4]; t[0] =~ t[0];
        t[1] =~ t[1]; t[2] =~ t[2]; t[3] =~ t[3];
        t[4] =~ t[4]; t[0] &= x[1]; t[1] &= x[2];
        t[2] &= x[3]; t[3] &= x[4]; t[4] &= x[0];
        x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3];
        x[3] ^= t[4]; x[4] ^= t[0]; x[1] ^= x[0];
        x[0] ^= x[4]; x[3] ^= x[2]; x[2] =~ x[2];

        x[0] ^= (x[0]>>19 | x[0]<<45) ^ (x[0]>>28 | x[0]<<36);
        x[1] ^= (x[1]>>61 | x[1]<< 3) ^ (x[1]>>39 | x[1]<<25);
        x[2] ^= (x[2]>> 1 | x[2]<<63) ^ (x[2]>> 6 | x[2]<<58);
        x[3] ^= (x[3]>>10 | x[3]<<54) ^ (x[3]>>17 | x[3]<<47);
        x[4] ^= (x[4]>> 7 | x[4]<<57) ^ (x[4]>>41 | x[4]<<23);
    }
}

static void ascon_load(struct ascon *c, const void *block)
{
    const unsigned char *p = block;
    uint64_t b = (uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 |
                 (uint64_t)p[2] << 40 | (uint64_t)p[3] << 32 |
                 (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 |
                 (uint64_t)p[6] <<  8 | (uint64_t)p[7] <<  0;
    c->x[0] ^= b;
}

static void ascon_push(struct ascon *c, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    if (!c->len) {
        ascon_init(c);
    }

    if (c->len & 7) {
        c->len &= 7;
        for (; c->len<8 && len; p++, len--) {
            c->buf[c->len++] = *p;
        }
        if (c->len == 8) {
            ascon_load(c, c->buf);
            ascon_permute(c);
        } else {
            return;
        }
    }

    for (; len >= 8; p += 8, len -= 8) {
        ascon_load(c, p);
        ascon_permute(c);
    }

    c->len = len + 8;
    for (int i = 0; i < (int)len; i++) {
        c->buf[i] = p[i];
    }
}

static void ascon_final(struct ascon *c, void *digest)
{
    if (!c->len) {
        ascon_init(c);
    }

    // Pad and load final block
    int i = c->len & 7;
    c->buf[i++] = 0x80;
    for (; i < 8; i++) {
        c->buf[i] = 0;
    }
    c->len = 0;  // reset to initial state
    ascon_load(c, c->buf);

    unsigned char *p = digest;
    for (int i = 0; i < 4; i++) {
        ascon_permute(c);
        p[i*8+0] = c->x[0] >> 56;
        p[i*8+1] = c->x[0] >> 48;
        p[i*8+2] = c->x[0] >> 40;
        p[i*8+3] = c->x[0] >> 32;
        p[i*8+4] = c->x[0] >> 24;
        p[i*8+5] = c->x[0] >> 16;
        p[i*8+6] = c->x[0] >>  8;
        p[i*8+7] = c->x[0] >>  0;
    }
}


#ifdef DEMO
// Compute a hash of standard input
// $ cc -DDEMO -O3 -o ascon ascon.c
#include <stdio.h>

int main(void)
{
    #if _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    struct ascon ctx[1] = {0};
    for (;;) {
        char buf[1<<12];
        int len = fread(buf, 1, sizeof(buf), stdin);
        if (!len) {
            break;
        }
        ascon_push(ctx, buf, len);
    }

    uint8_t digest[ASCON_DIGEST_LENGTH];
    ascon_final(ctx, digest);

    char hex[ASCON_DIGEST_LENGTH*2+1];
    for (int i = 0; i < ASCON_DIGEST_LENGTH; i++) {
        hex[i*2+0] = "0123456789abcdef"[digest[i]>>4];
        hex[i*2+1] = "0123456789abcdef"[digest[i]&15];
    }
    hex[ASCON_DIGEST_LENGTH*2] = '\n';
    fwrite(hex, 1, sizeof(hex), stdout);
}
#endif
