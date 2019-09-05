/* This is free and unencumbered software released into the public domain. */
#include <stddef.h>

/* Append data to a 16-bit X.25 CRC. Use 0 for the initial CRC.
 * Note: MVALink uses bitwise-NOT of X.25 for its checksum.
 */
static unsigned
crc16x25_update(unsigned crc, const void *buf, size_t len)
{
    size_t i;
    const unsigned char *p = buf;
    crc ^= 0xffff;
    for (i = 0; i < len; i++) {
        unsigned t = p[i] ^ (crc & 0xff);
        t ^= t<<4 & 0xff;
        crc = crc>>8 ^ t<<8 ^ t<<3 ^ t>>4;
    }
    return crc ^ 0xffff;
}
