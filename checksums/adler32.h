/* This is free and unencumbered software released into the public domain. */
#include <stddef.h>

/* Append data to an Adler32 checksum. Use 1 for the initial checksum.
 */
static unsigned long
adler32_update(unsigned long sum, const void *data, size_t len)
{
    size_t i;
    const unsigned char *p = data;
    unsigned long a = sum & 0xffff;
    unsigned long b = sum >> 16;
    for (i = 0; i < len; i++) {
        a = (a + p[i]) % 0xfff1UL;
        b = (b + a) % 0xfff1UL;
    }
    return (b << 16) | a;
}

/* Append two separately-computed Adler32 checksums.
 * If len2 does not fit in an unsigned long, pass (len2 % 65521).
 */
static unsigned long
adler32_combine(unsigned long a1, unsigned long a2, unsigned long len2)
{
    static const unsigned long base = 0xfff1UL;
    unsigned long sum1;
    unsigned long sum2;
    unsigned long rem;

    rem = len2 % base;
    sum1 = a1 & 0xffffUL;
    sum2 = rem * sum1;
    sum2 %= base;
    sum1 += (a2 & 0xffff) + base - 1;
    sum2 += ((a1 >> 16) & 0xffffUL) +
            ((a2 >> 16) & 0xffffUL) + base - rem;
    if (sum1 >= base)
        sum1 -= base;
    if (sum1 >= base)
        sum1 -= base;
    if (sum2 >= (base << 1))
        sum2 -= (base << 1);
    if (sum2 >= base)
        sum2 -= base;
    return sum1 | (sum2 << 16);
}
