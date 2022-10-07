// Straightforward UTF-8 encoder and decoder.
// This is free and unencumbered software released into the public domain.
#include <stddef.h>
#include <stdint.h>
#ifndef NDEBUG
#  if _MSC_VER
#    define ASSERT(c) if (!(c)) __debugbreak();
#  elif __GNUC__
#    define ASSERT(c) if (!(c)) __builtin_trap();
#  else
#    define ASSERT(c) if (!(c)) *(volatile int *)0 = 0;
#  endif
#endif

// Encode a codepoint into the buffer. Returns write length (1-4).
// Invalid codepoints are encoded as U+FFFD.
int utf8encode(char *s, int32_t c)
{
    if (c<0 || (c>=0xd800 && c<=0xdfff) || c>0x10ffff) {
        c = 0xfffd;
    }
    switch ((c >= 0x80) + (c >= 0x800) + (c >= 0x10000)) {
    case 0: s[0] = 0x00 | ((c >>  0)     ); return 1;
    case 1: s[0] = 0xc0 | ((c >>  6)     );
            s[1] = 0x80 | ((c >>  0) & 63); return 2;
    case 2: s[0] = 0xe0 | ((c >> 12)     );
            s[1] = 0x80 | ((c >>  6) & 63);
            s[2] = 0x80 | ((c >>  0) & 63); return 3;
    case 3: s[0] = 0xf0 | ((c >> 18)     );
            s[1] = 0x80 | ((c >> 12) & 63);
            s[2] = 0x80 | ((c >>  6) & 63);
            s[3] = 0x80 | ((c >>  0) & 63); return 4;
    }
    ASSERT(0);
}

// Decode a codepoint from the buffer. Returns read length (1-4).
// Invalid bytes are decoded as U+FFFD. Length must be non-zero.
int utf8decode(const char *s, size_t len, int32_t *c)
{
    ASSERT(len);
    switch (s[0]&0xf0) {
    default  : *c = (int32_t)(s[0]&0xff) << 0;
               if (*c > 0x7f) break;
               return 1;
    case 0xc0:
    case 0xd0: if (len < 2) break;
               if ((s[1]&0xc0) != 0x80) break;
               *c = (int32_t)(s[0]&0x1f) << 6 |
                    (int32_t)(s[1]&0x3f) << 0;
               if (*c < 0x80) {
                   break;
               }
               return 2;
    case 0xe0: if (len < 3) break;
               if ((s[1]&0xc0) != 0x80) break;
               if ((s[2]&0xc0) != 0x80) break;
               *c = (int32_t)(s[0]&0x0f) << 12 |
                    (int32_t)(s[1]&0x3f) <<  6 |
                    (int32_t)(s[2]&0x3f) <<  0;
               if (*c<0x800 || (*c>=0xd800 && *c<=0xdfff)) {
                   break;
               }
               return 3;
    case 0xf0: if (len < 4) break;
               if ((s[1]&0xc0) != 0x80) break;
               if ((s[2]&0xc0) != 0x80) break;
               if ((s[3]&0xc0) != 0x80) break;
               *c = (int32_t)(s[0]&0x0f) << 18 |
                    (int32_t)(s[1]&0x3f) << 12 |
                    (int32_t)(s[2]&0x3f) <<  6 |
                    (int32_t)(s[3]&0x3f) <<  0;
               if (*c<0x10000 || *c>0x10ffff) {
                   break;
               }
               return 4;
    }
    *c = 0xfffd;
    return 1;
}


#if TEST
int main(void)
{
    for (int32_t c = 0; c <= 0x10ffff; c++) {
        if (c >= 0xd800 && c <= 0xdfff) {
            continue;
        }
        char s[4];
        int32_t r;
        int ilen = utf8encode(s, c);
        int olen = utf8decode(s, ilen, &r);
        ASSERT(ilen == olen);
        ASSERT(r == c);
    }
}
#endif
