// Branchless RFC 1035 domain name encoder
// This is free and unencumbered software released into the public domain.

// Encode a domain name using length-prefixed labels (RFC 1035). The
// destination length will be one byte longer than the source length,
// and buffers may overlap only if dst < src.
void rfc1035encode(unsigned char *dst, unsigned char *src, int len)
{
    int c = -1;
    *dst++ = 0;
    for (int i = 0; i < len; i++) {
        unsigned char copy = src[i];
        unsigned char keep = copy != '.';
        dst[i]  = copy - (-!keep & '.');
        dst[c] += keep;
        c      &= -keep;
        c      |= -!keep & i;
    }
}


#ifdef TEST
// $ cc -DTEST -o rfc1035encode rfc1035encode.c
// $ gdb -ex run ./rfc1035encode
int main(void)
{
    #define ASSERT(c) if (!(c)) *(volatile int *)0 = 0
    unsigned char test[]   = "$cdn.example.nullprogram.com";
    unsigned char expect[] = "\3cdn\7example\13nullprogram\3com";
    unsigned char *src = test + 1;
    int srclen = sizeof(test) - 2;
    unsigned char *dst = test;
    int dstlen = srclen + 1;
    rfc1035encode(dst, src, srclen);
    for (int i = 0; i < dstlen; i++) {
        ASSERT(dst[i] == expect[i]);
    }
}
#endif


#ifdef DEMO
// $ cc -DDEMO -o rfc1035encode rfc1035encode.c
// $ ./rfc1035encode cdn.example.nullprogram.com
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        int len = strlen(argv[i]);
        memmove(argv[i]+1, argv[i], len);
        rfc1035encode(argv[i], argv[i]+1, len);
        fwrite(argv[i], len+1, 1, stdout);
        putchar('\n');
    }
    fflush(stdout);
    return ferror(stdout);
}
#endif
