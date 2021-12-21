// This is free and unencumbered software released into the public domain.
#include "uuidgen.h"
#include <string.h>

// Platform-specific seeding system call
#if defined(_WIN32)
#  include <stdlib.h>      // abort(3)
#  include <windows.h>     // (for ntsecapi.h)
#  include <ntsecapi.h>    // RtlGenRandom()
#  ifdef _MSC_VER
#    pragma comment(lib, "advapi32")
#  endif
#elif defined(__linux__)
#  include <sys/random.h>  // getrandom(2)
#else // OpenBSD, FreeBSD, macOS, etc.
#  include <stdlib.h>      // arc4random_buf(3)
#endif

void
uuidgen(struct uuidgen *g, char *buf)
{
    if (g->s[0] == 0 && g->s[1] == 0) {
        // First run, populate with random seed
        #if defined(_WIN32)
        if (!RtlGenRandom(g->s + 2, 56)) {
            abort();  // should never happen
        }
        #elif defined(__linux__)
        getrandom(g->s + 2, 56, 0);
        #else
        arc4random_buf(g->s + 2, 56);
        #endif
    }

    if (g->n != 0) {
        // Copy and discard a pre-generated UUID
        memcpy(buf, g->tmp[--g->n], 36);
        return;
    }

    // Salsa hash of counter and seed (8 rounds)
    uint32_t x[16];
    memcpy(x, g->s, sizeof(x));
    for (int i = 0; i < 8; i += 2) {
        x[ 0] += x[ 4]; x[12] = (((x[12]^x[ 0]) << 16)|((x[12]^x[ 0]) >> 16));
        x[ 8] += x[12]; x[ 4] = (((x[ 4]^x[ 8]) << 12)|((x[ 4]^x[ 8]) >> 20));
        x[ 0] += x[ 4]; x[12] = (((x[12]^x[ 0]) <<  8)|((x[12]^x[ 0]) >> 24));
        x[ 8] += x[12]; x[ 4] = (((x[ 4]^x[ 8]) <<  7)|((x[ 4]^x[ 8]) >> 25));
        x[ 1] += x[ 5]; x[13] = (((x[13]^x[ 1]) << 16)|((x[13]^x[ 1]) >> 16));
        x[ 9] += x[13]; x[ 5] = (((x[ 5]^x[ 9]) << 12)|((x[ 5]^x[ 9]) >> 20));
        x[ 1] += x[ 5]; x[13] = (((x[13]^x[ 1]) <<  8)|((x[13]^x[ 1]) >> 24));
        x[ 9] += x[13]; x[ 5] = (((x[ 5]^x[ 9]) <<  7)|((x[ 5]^x[ 9]) >> 25));
        x[ 2] += x[ 6]; x[14] = (((x[14]^x[ 2]) << 16)|((x[14]^x[ 2]) >> 16));
        x[10] += x[14]; x[ 6] = (((x[ 6]^x[10]) << 12)|((x[ 6]^x[10]) >> 20));
        x[ 2] += x[ 6]; x[14] = (((x[14]^x[ 2]) <<  8)|((x[14]^x[ 2]) >> 24));
        x[10] += x[14]; x[ 6] = (((x[ 6]^x[10]) <<  7)|((x[ 6]^x[10]) >> 25));
        x[ 3] += x[ 7]; x[15] = (((x[15]^x[ 3]) << 16)|((x[15]^x[ 3]) >> 16));
        x[11] += x[15]; x[ 7] = (((x[ 7]^x[11]) << 12)|((x[ 7]^x[11]) >> 20));
        x[ 3] += x[ 7]; x[15] = (((x[15]^x[ 3]) <<  8)|((x[15]^x[ 3]) >> 24));
        x[11] += x[15]; x[ 7] = (((x[ 7]^x[11]) <<  7)|((x[ 7]^x[11]) >> 25));
        x[ 0] += x[ 5]; x[15] = (((x[15]^x[ 0]) << 16)|((x[15]^x[ 0]) >> 16));
        x[10] += x[15]; x[ 5] = (((x[ 5]^x[10]) << 12)|((x[ 5]^x[10]) >> 20));
        x[ 0] += x[ 5]; x[15] = (((x[15]^x[ 0]) <<  8)|((x[15]^x[ 0]) >> 24));
        x[10] += x[15]; x[ 5] = (((x[ 5]^x[10]) <<  7)|((x[ 5]^x[10]) >> 25));
        x[ 1] += x[ 6]; x[12] = (((x[12]^x[ 1]) << 16)|((x[12]^x[ 1]) >> 16));
        x[11] += x[12]; x[ 6] = (((x[ 6]^x[11]) << 12)|((x[ 6]^x[11]) >> 20));
        x[ 1] += x[ 6]; x[12] = (((x[12]^x[ 1]) <<  8)|((x[12]^x[ 1]) >> 24));
        x[11] += x[12]; x[ 6] = (((x[ 6]^x[11]) <<  7)|((x[ 6]^x[11]) >> 25));
        x[ 2] += x[ 7]; x[13] = (((x[13]^x[ 2]) << 16)|((x[13]^x[ 2]) >> 16));
        x[ 8] += x[13]; x[ 7] = (((x[ 7]^x[ 8]) << 12)|((x[ 7]^x[ 8]) >> 20));
        x[ 2] += x[ 7]; x[13] = (((x[13]^x[ 2]) <<  8)|((x[13]^x[ 2]) >> 24));
        x[ 8] += x[13]; x[ 7] = (((x[ 7]^x[ 8]) <<  7)|((x[ 7]^x[ 8]) >> 25));
        x[ 3] += x[ 4]; x[14] = (((x[14]^x[ 3]) << 16)|((x[14]^x[ 3]) >> 16));
        x[ 9] += x[14]; x[ 4] = (((x[ 4]^x[ 9]) << 12)|((x[ 4]^x[ 9]) >> 20));
        x[ 3] += x[ 4]; x[14] = (((x[14]^x[ 3]) <<  8)|((x[14]^x[ 3]) >> 24));
        x[ 9] += x[14]; x[ 4] = (((x[ 4]^x[ 9]) <<  7)|((x[ 4]^x[ 9]) >> 25));
    }
    for (int i = 0; i < 16; i++) {
        x[i] += g->s[i];
    }

    // Increment Salsa counter
    if (!++g->s[0]) {
        g->s[1]++;
    }

    // Clamp some nibbles to "89ab"
    x[ 2] = (x[ 2] & 0x3fffffffU) | 0x80000000U;
    x[ 6] = (x[ 6] & 0x3fffffffU) | 0x80000000U;
    x[10] = (x[10] & 0x3fffffffU) | 0x80000000U;
    x[14] = (x[14] & 0x3fffffffU) | 0x80000000U;

    // Generate 4 UUIDs
    for (int i = 0; i < 4; i++) {
        static const char hex[256] = "0123456789abcdef";
        char *d = i ? g->tmp[i-1] : buf;
        uint32_t *s = x + 4*i;
        d[ 0] = hex[s[0] >> 28 & 0x0f];
        d[ 1] = hex[s[0] >> 24 & 0x0f];
        d[ 2] = hex[s[0] >> 20 & 0x0f];
        d[ 3] = hex[s[0] >> 16 & 0x0f];
        d[ 4] = hex[s[0] >> 12 & 0x0f];
        d[ 5] = hex[s[0] >>  8 & 0x0f];
        d[ 6] = hex[s[0] >>  4 & 0x0f];
        d[ 7] = hex[s[0] >>  0 & 0x0f];
        d[ 8] = '-';
        d[ 9] = hex[s[1] >> 28 & 0x0f];
        d[10] = hex[s[1] >> 24 & 0x0f];
        d[11] = hex[s[1] >> 20 & 0x0f];
        d[12] = hex[s[1] >> 16 & 0x0f];
        d[13] = '-';
        d[14] = '4';
        d[15] = hex[s[1] >>  8 & 0x0f];
        d[16] = hex[s[1] >>  4 & 0x0f];
        d[17] = hex[s[1] >>  0 & 0x0f];
        d[18] = '-';
        d[19] = hex[s[2] >> 28 & 0x0f];
        d[20] = hex[s[2] >> 24 & 0x0f];
        d[21] = hex[s[2] >> 20 & 0x0f];
        d[22] = hex[s[2] >> 16 & 0x0f];
        d[23] = '-';
        d[24] = hex[s[2] >> 12 & 0x0f];
        d[25] = hex[s[2] >>  8 & 0x0f];
        d[26] = hex[s[2] >>  4 & 0x0f];
        d[27] = hex[s[2] >>  0 & 0x0f];
        d[28] = hex[s[3] >> 28 & 0x0f];
        d[29] = hex[s[3] >> 24 & 0x0f];
        d[30] = hex[s[3] >> 20 & 0x0f];
        d[31] = hex[s[3] >> 16 & 0x0f];
        d[32] = hex[s[3] >> 12 & 0x0f];
        d[33] = hex[s[3] >>  8 & 0x0f];
        d[34] = hex[s[3] >>  4 & 0x0f];
        d[35] = hex[s[3] >>  0 & 0x0f];
    }
}
