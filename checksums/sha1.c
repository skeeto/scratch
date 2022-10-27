// Portable SHA1 implementation in C
//
//   struct sha1 ctx = {0};
//   unsigned char digest[SHA1LEN];
//   sha1push(&ctx, "Hello, ", 7);
//   sha1push(&ctx, "world!", 6);
//   sha1sum(&ctx, digest);
//
// This is free and unencumbered software released into the public domain.

// Interface
#include <stddef.h>
#include <stdint.h>

#define SHA1LEN 20

struct sha1 {
    uint64_t n;  // zero-initialize before first sha1push/sha1sum
    uint32_t h0, h1, h2, h3, h4;
    unsigned char c[64];
};

void sha1push(struct sha1 *, const void *, size_t);
void sha1sum(const struct sha1 *, void *);
void hmacsha1key(struct sha1 *, const void *, size_t);
void hmacsha1sum(const struct sha1 *, const void *, size_t, void *);
long totpsha1(const void *, size_t, int64_t);

// Implementation

static void
sha1absorb(struct sha1 *s, const unsigned char *p)
{
    uint32_t w[80], a=s->h0, b=s->h1, c=s->h2, d=s->h3, e=s->h4;
    uint32_t m1=0x5a827999, m2=0x6ed9eba1, m3=0x8f1bbcdc, m4=0xca62c1d6;

    w[ 0] = (uint32_t)p[ 0]<<24|(uint32_t)p[ 1]<<16|(uint32_t)p[ 2]<<8|p[ 3];
    w[ 1] = (uint32_t)p[ 4]<<24|(uint32_t)p[ 5]<<16|(uint32_t)p[ 6]<<8|p[ 7];
    w[ 2] = (uint32_t)p[ 8]<<24|(uint32_t)p[ 9]<<16|(uint32_t)p[10]<<8|p[11];
    w[ 3] = (uint32_t)p[12]<<24|(uint32_t)p[13]<<16|(uint32_t)p[14]<<8|p[15];
    w[ 4] = (uint32_t)p[16]<<24|(uint32_t)p[17]<<16|(uint32_t)p[18]<<8|p[19];
    w[ 5] = (uint32_t)p[20]<<24|(uint32_t)p[21]<<16|(uint32_t)p[22]<<8|p[23];
    w[ 6] = (uint32_t)p[24]<<24|(uint32_t)p[25]<<16|(uint32_t)p[26]<<8|p[27];
    w[ 7] = (uint32_t)p[28]<<24|(uint32_t)p[29]<<16|(uint32_t)p[30]<<8|p[31];
    w[ 8] = (uint32_t)p[32]<<24|(uint32_t)p[33]<<16|(uint32_t)p[34]<<8|p[35];
    w[ 9] = (uint32_t)p[36]<<24|(uint32_t)p[37]<<16|(uint32_t)p[38]<<8|p[39];
    w[10] = (uint32_t)p[40]<<24|(uint32_t)p[41]<<16|(uint32_t)p[42]<<8|p[43];
    w[11] = (uint32_t)p[44]<<24|(uint32_t)p[45]<<16|(uint32_t)p[46]<<8|p[47];
    w[12] = (uint32_t)p[48]<<24|(uint32_t)p[49]<<16|(uint32_t)p[50]<<8|p[51];
    w[13] = (uint32_t)p[52]<<24|(uint32_t)p[53]<<16|(uint32_t)p[54]<<8|p[55];
    w[14] = (uint32_t)p[56]<<24|(uint32_t)p[57]<<16|(uint32_t)p[58]<<8|p[59];
    w[15] = (uint32_t)p[60]<<24|(uint32_t)p[61]<<16|(uint32_t)p[62]<<8|p[63];
    w[16] = w[13] ^ w[ 8] ^ w[ 2] ^ w[ 0];  w[16] = w[16]<<1 | w[16]>>31;
    w[17] = w[14] ^ w[ 9] ^ w[ 3] ^ w[ 1];  w[17] = w[17]<<1 | w[17]>>31;
    w[18] = w[15] ^ w[10] ^ w[ 4] ^ w[ 2];  w[18] = w[18]<<1 | w[18]>>31;
    w[19] = w[16] ^ w[11] ^ w[ 5] ^ w[ 3];  w[19] = w[19]<<1 | w[19]>>31;
    w[20] = w[17] ^ w[12] ^ w[ 6] ^ w[ 4];  w[20] = w[20]<<1 | w[20]>>31;
    w[21] = w[18] ^ w[13] ^ w[ 7] ^ w[ 5];  w[21] = w[21]<<1 | w[21]>>31;
    w[22] = w[19] ^ w[14] ^ w[ 8] ^ w[ 6];  w[22] = w[22]<<1 | w[22]>>31;
    w[23] = w[20] ^ w[15] ^ w[ 9] ^ w[ 7];  w[23] = w[23]<<1 | w[23]>>31;
    w[24] = w[21] ^ w[16] ^ w[10] ^ w[ 8];  w[24] = w[24]<<1 | w[24]>>31;
    w[25] = w[22] ^ w[17] ^ w[11] ^ w[ 9];  w[25] = w[25]<<1 | w[25]>>31;
    w[26] = w[23] ^ w[18] ^ w[12] ^ w[10];  w[26] = w[26]<<1 | w[26]>>31;
    w[27] = w[24] ^ w[19] ^ w[13] ^ w[11];  w[27] = w[27]<<1 | w[27]>>31;
    w[28] = w[25] ^ w[20] ^ w[14] ^ w[12];  w[28] = w[28]<<1 | w[28]>>31;
    w[29] = w[26] ^ w[21] ^ w[15] ^ w[13];  w[29] = w[29]<<1 | w[29]>>31;
    w[30] = w[27] ^ w[22] ^ w[16] ^ w[14];  w[30] = w[30]<<1 | w[30]>>31;
    w[31] = w[28] ^ w[23] ^ w[17] ^ w[15];  w[31] = w[31]<<1 | w[31]>>31;
    w[32] = w[29] ^ w[24] ^ w[18] ^ w[16];  w[32] = w[32]<<1 | w[32]>>31;
    w[33] = w[30] ^ w[25] ^ w[19] ^ w[17];  w[33] = w[33]<<1 | w[33]>>31;
    w[34] = w[31] ^ w[26] ^ w[20] ^ w[18];  w[34] = w[34]<<1 | w[34]>>31;
    w[35] = w[32] ^ w[27] ^ w[21] ^ w[19];  w[35] = w[35]<<1 | w[35]>>31;
    w[36] = w[33] ^ w[28] ^ w[22] ^ w[20];  w[36] = w[36]<<1 | w[36]>>31;
    w[37] = w[34] ^ w[29] ^ w[23] ^ w[21];  w[37] = w[37]<<1 | w[37]>>31;
    w[38] = w[35] ^ w[30] ^ w[24] ^ w[22];  w[38] = w[38]<<1 | w[38]>>31;
    w[39] = w[36] ^ w[31] ^ w[25] ^ w[23];  w[39] = w[39]<<1 | w[39]>>31;
    w[40] = w[37] ^ w[32] ^ w[26] ^ w[24];  w[40] = w[40]<<1 | w[40]>>31;
    w[41] = w[38] ^ w[33] ^ w[27] ^ w[25];  w[41] = w[41]<<1 | w[41]>>31;
    w[42] = w[39] ^ w[34] ^ w[28] ^ w[26];  w[42] = w[42]<<1 | w[42]>>31;
    w[43] = w[40] ^ w[35] ^ w[29] ^ w[27];  w[43] = w[43]<<1 | w[43]>>31;
    w[44] = w[41] ^ w[36] ^ w[30] ^ w[28];  w[44] = w[44]<<1 | w[44]>>31;
    w[45] = w[42] ^ w[37] ^ w[31] ^ w[29];  w[45] = w[45]<<1 | w[45]>>31;
    w[46] = w[43] ^ w[38] ^ w[32] ^ w[30];  w[46] = w[46]<<1 | w[46]>>31;
    w[47] = w[44] ^ w[39] ^ w[33] ^ w[31];  w[47] = w[47]<<1 | w[47]>>31;
    w[48] = w[45] ^ w[40] ^ w[34] ^ w[32];  w[48] = w[48]<<1 | w[48]>>31;
    w[49] = w[46] ^ w[41] ^ w[35] ^ w[33];  w[49] = w[49]<<1 | w[49]>>31;
    w[50] = w[47] ^ w[42] ^ w[36] ^ w[34];  w[50] = w[50]<<1 | w[50]>>31;
    w[51] = w[48] ^ w[43] ^ w[37] ^ w[35];  w[51] = w[51]<<1 | w[51]>>31;
    w[52] = w[49] ^ w[44] ^ w[38] ^ w[36];  w[52] = w[52]<<1 | w[52]>>31;
    w[53] = w[50] ^ w[45] ^ w[39] ^ w[37];  w[53] = w[53]<<1 | w[53]>>31;
    w[54] = w[51] ^ w[46] ^ w[40] ^ w[38];  w[54] = w[54]<<1 | w[54]>>31;
    w[55] = w[52] ^ w[47] ^ w[41] ^ w[39];  w[55] = w[55]<<1 | w[55]>>31;
    w[56] = w[53] ^ w[48] ^ w[42] ^ w[40];  w[56] = w[56]<<1 | w[56]>>31;
    w[57] = w[54] ^ w[49] ^ w[43] ^ w[41];  w[57] = w[57]<<1 | w[57]>>31;
    w[58] = w[55] ^ w[50] ^ w[44] ^ w[42];  w[58] = w[58]<<1 | w[58]>>31;
    w[59] = w[56] ^ w[51] ^ w[45] ^ w[43];  w[59] = w[59]<<1 | w[59]>>31;
    w[60] = w[57] ^ w[52] ^ w[46] ^ w[44];  w[60] = w[60]<<1 | w[60]>>31;
    w[61] = w[58] ^ w[53] ^ w[47] ^ w[45];  w[61] = w[61]<<1 | w[61]>>31;
    w[62] = w[59] ^ w[54] ^ w[48] ^ w[46];  w[62] = w[62]<<1 | w[62]>>31;
    w[63] = w[60] ^ w[55] ^ w[49] ^ w[47];  w[63] = w[63]<<1 | w[63]>>31;
    w[64] = w[61] ^ w[56] ^ w[50] ^ w[48];  w[64] = w[64]<<1 | w[64]>>31;
    w[65] = w[62] ^ w[57] ^ w[51] ^ w[49];  w[65] = w[65]<<1 | w[65]>>31;
    w[66] = w[63] ^ w[58] ^ w[52] ^ w[50];  w[66] = w[66]<<1 | w[66]>>31;
    w[67] = w[64] ^ w[59] ^ w[53] ^ w[51];  w[67] = w[67]<<1 | w[67]>>31;
    w[68] = w[65] ^ w[60] ^ w[54] ^ w[52];  w[68] = w[68]<<1 | w[68]>>31;
    w[69] = w[66] ^ w[61] ^ w[55] ^ w[53];  w[69] = w[69]<<1 | w[69]>>31;
    w[70] = w[67] ^ w[62] ^ w[56] ^ w[54];  w[70] = w[70]<<1 | w[70]>>31;
    w[71] = w[68] ^ w[63] ^ w[57] ^ w[55];  w[71] = w[71]<<1 | w[71]>>31;
    w[72] = w[69] ^ w[64] ^ w[58] ^ w[56];  w[72] = w[72]<<1 | w[72]>>31;
    w[73] = w[70] ^ w[65] ^ w[59] ^ w[57];  w[73] = w[73]<<1 | w[73]>>31;
    w[74] = w[71] ^ w[66] ^ w[60] ^ w[58];  w[74] = w[74]<<1 | w[74]>>31;
    w[75] = w[72] ^ w[67] ^ w[61] ^ w[59];  w[75] = w[75]<<1 | w[75]>>31;
    w[76] = w[73] ^ w[68] ^ w[62] ^ w[60];  w[76] = w[76]<<1 | w[76]>>31;
    w[77] = w[74] ^ w[69] ^ w[63] ^ w[61];  w[77] = w[77]<<1 | w[77]>>31;
    w[78] = w[75] ^ w[70] ^ w[64] ^ w[62];  w[78] = w[78]<<1 | w[78]>>31;
    w[79] = w[76] ^ w[71] ^ w[65] ^ w[63];  w[79] = w[79]<<1 | w[79]>>31;

    e += (a<<5 | a>>27) + w[ 0] +  ((b&c) | (~b&d)) + m1;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[ 1] +  ((a&b) | (~a&c)) + m1;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[ 2] +  ((e&a) | (~e&b)) + m1;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[ 3] +  ((d&e) | (~d&a)) + m1;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[ 4] +  ((c&d) | (~c&e)) + m1;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[ 5] +  ((b&c) | (~b&d)) + m1;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[ 6] +  ((a&b) | (~a&c)) + m1;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[ 7] +  ((e&a) | (~e&b)) + m1;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[ 8] +  ((d&e) | (~d&a)) + m1;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[ 9] +  ((c&d) | (~c&e)) + m1;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[10] +  ((b&c) | (~b&d)) + m1;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[11] +  ((a&b) | (~a&c)) + m1;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[12] +  ((e&a) | (~e&b)) + m1;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[13] +  ((d&e) | (~d&a)) + m1;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[14] +  ((c&d) | (~c&e)) + m1;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[15] +  ((b&c) | (~b&d)) + m1;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[16] +  ((a&b) | (~a&c)) + m1;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[17] +  ((e&a) | (~e&b)) + m1;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[18] +  ((d&e) | (~d&a)) + m1;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[19] +  ((c&d) | (~c&e)) + m1;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[20] +    (b ^ c ^ d)    + m2;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[21] +    (a ^ b ^ c)    + m2;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[22] +    (e ^ a ^ b)    + m2;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[23] +    (d ^ e ^ a)    + m2;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[24] +    (c ^ d ^ e)    + m2;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[25] +    (b ^ c ^ d)    + m2;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[26] +    (a ^ b ^ c)    + m2;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[27] +    (e ^ a ^ b)    + m2;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[28] +    (d ^ e ^ a)    + m2;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[29] +    (c ^ d ^ e)    + m2;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[30] +    (b ^ c ^ d)    + m2;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[31] +    (a ^ b ^ c)    + m2;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[32] +    (e ^ a ^ b)    + m2;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[33] +    (d ^ e ^ a)    + m2;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[34] +    (c ^ d ^ e)    + m2;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[35] +    (b ^ c ^ d)    + m2;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[36] +    (a ^ b ^ c)    + m2;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[37] +    (e ^ a ^ b)    + m2;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[38] +    (d ^ e ^ a)    + m2;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[39] +    (c ^ d ^ e)    + m2;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[40] +((b&c)|(b&d)|(c&d))+ m3;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[41] +((a&b)|(a&c)|(b&c))+ m3;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[42] +((e&a)|(e&b)|(a&b))+ m3;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[43] +((d&e)|(d&a)|(e&a))+ m3;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[44] +((c&d)|(c&e)|(d&e))+ m3;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[45] +((b&c)|(b&d)|(c&d))+ m3;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[46] +((a&b)|(a&c)|(b&c))+ m3;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[47] +((e&a)|(e&b)|(a&b))+ m3;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[48] +((d&e)|(d&a)|(e&a))+ m3;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[49] +((c&d)|(c&e)|(d&e))+ m3;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[50] +((b&c)|(b&d)|(c&d))+ m3;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[51] +((a&b)|(a&c)|(b&c))+ m3;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[52] +((e&a)|(e&b)|(a&b))+ m3;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[53] +((d&e)|(d&a)|(e&a))+ m3;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[54] +((c&d)|(c&e)|(d&e))+ m3;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[55] +((b&c)|(b&d)|(c&d))+ m3;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[56] +((a&b)|(a&c)|(b&c))+ m3;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[57] +((e&a)|(e&b)|(a&b))+ m3;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[58] +((d&e)|(d&a)|(e&a))+ m3;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[59] +((c&d)|(c&e)|(d&e))+ m3;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[60] +    (b ^ c ^ d)    + m4;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[61] +    (a ^ b ^ c)    + m4;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[62] +    (e ^ a ^ b)    + m4;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[63] +    (d ^ e ^ a)    + m4;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[64] +    (c ^ d ^ e)    + m4;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[65] +    (b ^ c ^ d)    + m4;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[66] +    (a ^ b ^ c)    + m4;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[67] +    (e ^ a ^ b)    + m4;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[68] +    (d ^ e ^ a)    + m4;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[69] +    (c ^ d ^ e)    + m4;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[70] +    (b ^ c ^ d)    + m4;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[71] +    (a ^ b ^ c)    + m4;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[72] +    (e ^ a ^ b)    + m4;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[73] +    (d ^ e ^ a)    + m4;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[74] +    (c ^ d ^ e)    + m4;  c = c<<30 | c>>2;
    e += (a<<5 | a>>27) + w[75] +    (b ^ c ^ d)    + m4;  b = b<<30 | b>>2;
    d += (e<<5 | e>>27) + w[76] +    (a ^ b ^ c)    + m4;  a = a<<30 | a>>2;
    c += (d<<5 | d>>27) + w[77] +    (e ^ a ^ b)    + m4;  e = e<<30 | e>>2;
    b += (c<<5 | c>>27) + w[78] +    (d ^ e ^ a)    + m4;  d = d<<30 | d>>2;
    a += (b<<5 | b>>27) + w[79] +    (c ^ d ^ e)    + m4;  c = c<<30 | c>>2;

    s->h0+=a; s->h1+=b; s->h2+=c; s->h3+=d; s->h4+=e;
}

void
sha1push(struct sha1 *s, const void *buf, size_t len)
{
    if (!s->n) {
        s->h0 = 0x67452301;
        s->h1 = 0xefcdab89;
        s->h2 = 0x98badcfe;
        s->h3 = 0x10325476;
        s->h4 = 0xc3d2e1f0;
    }

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
    struct sha1 t;
    if (!s->n) {
        t.n = 0;
        sha1push(&t, 0, 0);
    } else {
        t = *s;
    }

    int n = t.n & 63;
    t.n *= 8;
    t.c[n++] = 0x80;
    if (n > 56) {
        unsigned char buf[64] = {
            [56]=t.n>>56, [57]=t.n>>48, [58]=t.n>>40, [59]=t.n>>32,
            [60]=t.n>>24, [61]=t.n>>16, [62]=t.n>> 8, [63]=t.n>> 0
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
        struct sha1 t = {0};
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
    s->n = 0;
    sha1push(s, k, 64);
}

void
hmacsha1key(struct sha1 *s, const void *key, size_t len)
{
    hmacsha1init(s, key, len, 0x36);
}

void
hmacsha1sum(const struct sha1 *s, const void *key, size_t len, void *digest)
{
    struct sha1 t;
    unsigned char tmp[SHA1LEN];
    sha1sum(s, tmp);
    hmacsha1init(&t, key, len, 0x5c);
    sha1push(&t, tmp, SHA1LEN);
    sha1sum(&t, digest);
}

long
totpsha1(const void *key, size_t len, int64_t epoch)
{
    struct sha1 ctx;
    hmacsha1key(&ctx, key, len);

    uint64_t e = epoch / 30;
    unsigned char m[] = {e>>56, e>>48, e>>40, e>>32, e>>24, e>>16, e>>8, e};
    sha1push(&ctx, m, sizeof(m));

    unsigned char mac[SHA1LEN];
    hmacsha1sum(&ctx, key, len, mac);
    int off = mac[SHA1LEN-1] & 15;
    uint32_t r = (uint32_t)mac[off+0] << 24 | (uint32_t)mac[off+1] << 16 |
                 (uint32_t)mac[off+2] <<  8 | (uint32_t)mac[off+3] <<  0;
    return (r & 0x7fffffff) % 1000000;
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

    struct sha1 ctx = {0};
    unsigned char digest[SHA1LEN];
    sha1push(&ctx, input, sizeof(input));
    sha1sum(&ctx, digest);
    assert(!memcmp(want, digest, SHA1LEN));

    for (int trim = 0; trim < 7; trim++) {
        unsigned char want[SHA1LEN];
        ctx.n = 0;
        sha1push(&ctx, input, sizeof(input)-trim);
        sha1sum(&ctx, want);

        for (int chunk = 1; chunk < 63; chunk += 3) {
            size_t len = sizeof(input) - trim;
            ctx.n = 0;
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

    assert(222821L == totpsha1("\x01\x02\x03\x04", 4, 1666143375));

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

    struct sha1 ctx = {0};
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
