// Portable SHA1 implementation in C
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>

// Interface

#define SHA1LEN 20
#define SHA1 {0,0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0,{0}}

struct sha1 {
    uint64_t n;
    uint32_t h0, h1, h2, h3, h4;
    unsigned char c[64];
};

void sha1push(struct sha1 *, const void *, size_t);
void sha1sum(const struct sha1 *, void *);
void hmacsha1key(struct sha1 *, const void *, size_t);
void hmacsha1sum(const struct sha1 *, const void *, size_t, void *);

// Implementation

static void
sha1absorb(struct sha1 *s, const unsigned char *p)
{
    uint32_t a=s->h0, b=s->h1, c=s->h2, d=s->h3, e=s->h4;

    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)p[i*4+0] << 24 | (uint32_t)p[i*4+1] << 16 |
               (uint32_t)p[i*4+2] <<  8 | (uint32_t)p[i*4+3] <<  0;
    }
    for (int i = 16; i < 80; i++) {
        uint32_t x = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = x<<1 | x>>31;
    }

    for (int i = 0; i < 20; i++) {
        uint32_t f = (b&c) | (~b&d);
        uint32_t t = (a<<5 | a>>27) + e + w[i] + f + 0x5a827999;
        e = d; d = c; c = b<<30|b>>2; b = a; a = t;
    }
    for (int i = 20; i < 40; i++) {
        uint32_t f = b ^ c ^ d;
        uint32_t t = (a<<5 | a>>27) + e + w[i] + f + 0x6ed9eba1;
        e = d; d = c; c = b<<30|b>>2; b = a; a = t;
    }
    for (int i = 40; i < 60; i++) {
        uint32_t f = (b&c) | (b&d) | (c&d);
        uint32_t t = (a<<5 | a>>27) + e + w[i] + f + 0x8f1bbcdc;
        e = d; d = c; c = b<<30|b>>2; b = a; a = t;
    }
    for (int i = 60; i < 80; i++) {
        uint32_t f = b ^ c ^ d;
        uint32_t t = (a<<5 | a>>27) + e + w[i] + f + 0xca62c1d6;
        e = d; d = c; c = b<<30|b>>2; b = a; a = t;
    }

    s->h0+=a; s->h1+=b; s->h2+=c; s->h3+=d; s->h4+=e;
}

void
sha1push(struct sha1 *s, const void *buf, size_t len)
{
    const unsigned char *p = buf;

    int n = s->n & 63;
    int r = 64 - n;
    s->n += len;
    if (n) {
        int amt = len<(size_t)r ? (int)len : r;
        for (int i = 0; i < amt; i++) {
            s->c[n+i] = p[i];
        }
        p += amt;
        len -= amt;
        if (amt == r) {
            sha1absorb(s, s->c);
        }
    }

    for (; len >= 64; len-=64, p+=64) {
        sha1absorb(s, p);
    }

    for (int rem = len, i = 0; i < rem; i++) {
        s->c[i] = p[i];
    }
}

void
sha1sum(const struct sha1 *s, void *digest)
{
    struct sha1 t = *s;

    int n = t.n & 63;
    t.n *= 8;
    t.c[n++] = 0x80;
    if (n > 56) {
        unsigned char buf[64] = {
            t.n >> 56, t.n >> 48, t.n >> 40, t.n >> 32,
            t.n >> 24, t.n >> 16, t.n >>  8, t.n >>  0
        };
        for (int i = n; i < 64; i++) {
            t.c[i] = 0;
        }
        sha1absorb(&t, t.c);
        sha1absorb(&t, buf);
    } else {
        for (int i = n; i < 56; i++) {
            t.c[i] = 0;
        }
        t.c[56] = t.n >> 56; t.c[57] = t.n >> 48;
        t.c[58] = t.n >> 40; t.c[59] = t.n >> 32;
        t.c[60] = t.n >> 24; t.c[61] = t.n >> 16;
        t.c[62] = t.n >>  8; t.c[63] = t.n >>  0;
        sha1absorb(&t, t.c);
    }

    unsigned char *p = digest;
    p[ 0] = t.h0>>24; p[ 1] = t.h0>>16; p[ 2] = t.h0>>8; p[ 3] = t.h0>>0;
    p[ 4] = t.h1>>24; p[ 5] = t.h1>>16; p[ 6] = t.h1>>8; p[ 7] = t.h1>>0;
    p[ 8] = t.h2>>24; p[ 9] = t.h2>>16; p[10] = t.h2>>8; p[11] = t.h2>>0;
    p[12] = t.h3>>24; p[13] = t.h3>>16; p[14] = t.h3>>8; p[15] = t.h3>>0;
    p[16] = t.h4>>24; p[17] = t.h4>>16; p[18] = t.h4>>8; p[19] = t.h4>>0;
}

static void
hmacsha1init(struct sha1 *s, const void *key, size_t len, uint8_t pad)
{
    unsigned char k[64] = {0};
    if (len > 64) {
        struct sha1 t = SHA1;
        sha1push(&t, key, len);
        sha1sum(&t, k);
    } else {
        const unsigned char *p = key;
        for (int i = 0; i < (int)len; i++) {
            k[i] = p[i];
        }
    }

    for (int i = 0; i < 64; i++) {
        k[i] ^= pad;
    }
    sha1push(s, k, 64);
}

void
hmacsha1key(struct sha1 *s, const void *key, size_t len)
{
    *s = (struct sha1)SHA1;
    hmacsha1init(s, key, len, 0x36);
}

void
hmacsha1sum(const struct sha1 *s, const void *key, size_t len, void *digest)
{
    struct sha1 t = SHA1;
    unsigned char tmp[SHA1LEN];
    sha1sum(s, tmp);
    hmacsha1init(&t, key, len, 0x5c);
    sha1push(&t, tmp, SHA1LEN);
    sha1sum(&t, digest);
}


#if TEST
// $ cc -DTEST -g3 -fsanitize=address,undefined -o test sha1.c
// $ ./test
#include <assert.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
    static unsigned char input[1L<<20];
    static const unsigned char want[] = {
        0x61, 0x32, 0x92, 0x72, 0x8f, 0x6a, 0xfd, 0x03, 0x8b, 0x81,
        0xe7, 0xfc, 0xea, 0x7d, 0x5e, 0x12, 0x66, 0xf1, 0x65, 0x0c
    };

    uint64_t rng = 1;
    for (int i = 0; i < 1L<<18; i++) {
        uint32_t x = (rng = rng*0x3243f6a8885a308d + 1) >> 32;
        input[i*4+0] = x >>  0; input[i*4+1] = x >>  8;
        input[i*4+2] = x >> 16; input[i*4+3] = x >> 24;
    }

    struct sha1 ctx = SHA1;
    unsigned char digest[SHA1LEN];
    sha1push(&ctx, input, sizeof(input));
    sha1sum(&ctx, digest);
    assert(!memcmp(want, digest, SHA1LEN));

    for (int trim = 0; trim < 7; trim++) {
        struct sha1 ctx = SHA1;
        unsigned char want[SHA1LEN];
        sha1push(&ctx, input, sizeof(input)-trim);
        sha1sum(&ctx, want);

        for (int chunk = 1; chunk < 63; chunk += 3) {
            struct sha1 ctx = (struct sha1)SHA1;
            size_t len = sizeof(input) - trim;
            for (size_t i = 0; i < len; i += chunk) {
                int r = len - i;
                sha1push(&ctx, input+i, r<chunk?r:chunk);
            }
            unsigned char got[SHA1LEN];
            sha1sum(&ctx, got);
            assert(!memcmp(want, got, SHA1LEN));
        }

    }

    unsigned char mac[SHA1LEN];
    static const char msg[] = "Hello, world!";
    static const char shortkey[] = "secretkey";
    static const unsigned char shortmac[] = {
        0xfb, 0xe7, 0x37, 0x4d, 0x75, 0xbf, 0x58, 0x3c, 0xf5, 0xbd,
        0x2d, 0x93, 0x82, 0x55, 0xce, 0x53, 0x85, 0x8a, 0x84, 0xd1
    };
    hmacsha1key(&ctx, shortkey, sizeof(shortkey)-1);
    sha1push(&ctx, msg, sizeof(msg)-1);
    hmacsha1sum(&ctx, shortkey, sizeof(shortkey)-1, mac);
    assert(!memcmp(shortmac, mac, SHA1LEN));
    static const char longkey[100];
    static const unsigned char longmac[] = {
        0x87, 0xf3, 0xb4, 0xd9, 0xe3, 0x37, 0xe5, 0x57, 0x2b, 0xbd,
        0xc7, 0xe2, 0x30, 0xc8, 0x03, 0xd9, 0x55, 0xf2, 0x33, 0x02
    };
    hmacsha1key(&ctx, longkey, sizeof(longkey));
    sha1push(&ctx, msg, sizeof(msg)-1);
    hmacsha1sum(&ctx, longkey, sizeof(longkey), mac);
    assert(!memcmp(longmac, mac, SHA1LEN));

    puts("All tests pass.");
    return 0;
}
#endif


#if BENCH
// $ cc -DBENCH -O3 -o sha1 sha1.c
// $ time ./sha1 <input
#include <stdio.h>

int
main(void)
{
    #if _WIN32
    int _setmode(int, int);
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    struct sha1 ctx = SHA1;
    unsigned char digest[SHA1LEN];
    for (;;) {
        char buf[1<<14];
        int len = fread(buf, 1, sizeof(buf), stdin);
        sha1push(&ctx, buf, len);
        if (len != (int)sizeof(buf)) {
            break;
        }
    }
    sha1sum(&ctx, digest);

    char print[41];
    for (int i = 0; i < 20; i++) {
        print[i*2+0] = "0123456789abcdef"[digest[i]>>4];
        print[i*2+1] = "0123456789abcdef"[digest[i]&15];
    }
    print[40] = '\n';
    fwrite(print, sizeof(print), 1, stdout);
    fflush(stdout);
    return ferror(stdin) || ferror(stdout);
}
#endif
