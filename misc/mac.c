// MAC address encode/decode/encrypt library
// This is free and unencumbered software released into the public domain.
#include <stdint.h>

// Encode a MAC address to a 17-byte, UTF-8 destination buffer. The
// destination buffer is lowercase and is not null-terminated.
void mac_encode(char *dst, uint64_t mac)
{
    static const char hex[16] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    };
    dst[ 0] = hex[mac >> 44 & 15];
    dst[ 1] = hex[mac >> 40 & 15]; dst[ 2] = 0x3a;
    dst[ 3] = hex[mac >> 36 & 15];
    dst[ 4] = hex[mac >> 32 & 15]; dst[ 5] = 0x3a;
    dst[ 6] = hex[mac >> 28 & 15];
    dst[ 7] = hex[mac >> 24 & 15]; dst[ 8] = 0x3a;
    dst[ 9] = hex[mac >> 20 & 15];
    dst[10] = hex[mac >> 16 & 15]; dst[11] = 0x3a;
    dst[12] = hex[mac >> 12 & 15];
    dst[13] = hex[mac >>  8 & 15]; dst[14] = 0x3a;
    dst[15] = hex[mac >>  4 & 15];
    dst[16] = hex[mac >>  0 & 15];
}

// Decode a 17-byte buffer containing a UTF-8 MAC address. Returns 0 if
// the input is malformed.
int mac_decode(const char *restrict src, uint64_t *mac)
{
    static const signed char t[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        +0, +1, +2, +3, +4, +5, +6, +7, +8, +9, -1, -1, -1, -1, -1, -1,
        -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };
    *mac = (uint64_t)t[src[ 0]&255] << 44 | (uint64_t)t[src[ 1]&255] << 40 |
           (uint64_t)t[src[ 3]&255] << 36 | (uint64_t)t[src[ 4]&255] << 32 |
           (uint64_t)t[src[ 6]&255] << 28 | (uint64_t)t[src[ 7]&255] << 24 |
           (uint64_t)t[src[ 9]&255] << 20 | (uint64_t)t[src[10]&255] << 16 |
           (uint64_t)t[src[12]&255] << 12 | (uint64_t)t[src[13]&255] <<  8 |
           (uint64_t)t[src[15]&255] <<  4 | (uint64_t)t[src[16]&255] <<  0;
    return !((int)(*mac >> 48) | (src[ 2] ^ 0x3a) | (src[ 5] ^ 0x3a) |
                                 (src[ 8] ^ 0x3a) | (src[11] ^ 0x3a) |
                                 (src[14] ^ 0x3a));
}

// Format-preserving encryption of a MAC address, randomly permuting the
// address space using a given key. This is a very weak cipher.
uint64_t mac_encrypt(uint64_t mac, uint64_t key)
{
    key += 1111111111111111111U; key ^= key >> 33;
    key *= 1111111111111111111U; key ^= key >> 33;
    key *= 1111111111111111111U; key ^= key >> 33;
    mac += key >>  0; mac &= 0xffffffffffffU;
    mac ^= mac >> 24; mac *= 0xcdbc095777a5U;
    mac -= key >> 16; mac &= 0xffffffffffffU;
    mac ^= mac >> 24; mac *= 0xd481eae9d751U;
    mac &= 0xffffffffffffU; mac ^= mac >> 24;
    return mac;
}

// Format-preserving decryption of a MAC address, inverting mac_encrypt.
uint64_t mac_decrypt(uint64_t mac, uint64_t key)
{
    key += 1111111111111111111U; key ^= key >> 33;
    key *= 1111111111111111111U; key ^= key >> 33;
    key *= 1111111111111111111U; key ^= key >> 33;
    mac ^= mac >> 24; mac *= 0x4cf572b9d1b1U;
    mac &= 0xffffffffffffU; mac ^= mac >> 24;
    mac += key >> 16; mac *= 0x758e265e982dU;
    mac &= 0xffffffffffffU; mac ^= mac >> 24;
    mac -= key >>  0; mac &= 0xffffffffffffU;
    return mac;
}


#if TEST
#include <stdio.h>

int main(void)
{
    long nfails = 0;
    char buf[18] = {0};
    uint64_t s = 1;

    for (long i = 0; i < 1L<<26; i++) {
        uint64_t tmp, mac = (s = s*0x3d7d900e0c4dU + 1) & 0xffffffffffff;
        mac_encode(buf, mac);
        if (!mac_decode(buf, &tmp) || tmp != mac) {
            nfails++;
            printf("FAIL: %012llx %s\n", (unsigned long long)mac, buf);
        }

        tmp = mac_encrypt(mac, i);
        if (mac_decrypt(tmp, i) != mac) {
            printf("FAIL: (encrypt) key=%016llx %s\n",
                   (unsigned long long)mac, buf);
        }
    }

    for (int i = 0; i < 17; i++) {
        mac_encode(buf, 0x1234abcdef56);
        buf[i] = 'x';
        uint64_t mac;
        if (mac_decode(buf, &mac)) {
            printf("FAIL: (malformed) %s\n", buf);
        }
    }

    if (!nfails) {
        puts("All tests pass.");
    }
    return !nfails;
}
#endif
