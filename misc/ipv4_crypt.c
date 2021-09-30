// Format-preserving IPv4 encryption
// Maps each IPv4 address onto a different IPv4 address via a 64-bit key.
//
//   int ipv4_encrypt(char *ip, const void *key);
//   int ipv4_decrypt(char *ip, const void *key);
//
// This is free and unencumbered software released into the public domain.

// Decode a quad-dotted IPv4 address string into a numerical address.
// Returns -1 for invalid input, otherwise the numerical address.
static long long
ipv4_decode(const char *s)
{
    unsigned long ip = 0;
    int c = 0, n = 0, v = 0;

    for (const char *p = s; ; p++) {
        switch (*p) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            v = v*10 + *p - '0';
            if (v > 255) return -1;
            n++;
            break;
        case '.': case 0:
            if (!n || c == 4) return -1;
            ip = ip<<8 | v;
            c++;
            if (!*p) {
                return c == 4 ? (long long)ip : -1LL;
            }
            n = v = 0;
            break;
        default:
            return -1;
        }
    }
}

// Encode a numerical IPv4 address into a quad-dotted address string. The
// destination buffer size must be at least 16 bytes.
static void
ipv4_encode(char *s, unsigned long ip)
{
    for (int i = 3; i >= 0; i--) {
        int v = ip>>(i*8) & 0xff;
        *s = '0' + v/100  ; s += v >= 100;
        *s = '0' + v/10%10; s += v >=  10;
        *s = '0' + v%10   ; s++;
        *s = i ? '.' : 0  ; s++;
    }
}

// Encrypt a quad-dotted IPv4 address in place using format-preserving
// encryption. The key size is 8 bytes, and the buffer must have room for
// at least 16 bytes. Returns 1 on success or 0 if the input was invalid.
int
ipv4_encrypt(char *s, const void *key)
{
    long long r = ipv4_decode(s);
    if (r < 0) {
        return 0;
    }

    const unsigned char *p = key;
    unsigned long k0 = (unsigned long)p[0] <<  0 | (unsigned long)p[1] <<  8 |
                       (unsigned long)p[2] << 16 | (unsigned long)p[3] << 24;
    unsigned long k1 = (unsigned long)p[4] <<  0 | (unsigned long)p[5] <<  8 |
                       (unsigned long)p[6] << 16 | (unsigned long)p[7] << 24;

    unsigned long ip = r;
                       ip += k0; ip &= 0xffffffffU; ip ^= ip >> 17;
    ip *= 0x9e485565U; ip += k1; ip &= 0xffffffffU; ip ^= ip >> 16;
    ip *= 0xef1d6b47U;           ip &= 0xffffffffU; ip ^= ip >> 16;
    ipv4_encode(s, ip ^ k0 ^ k1);
    return 1;
}

// Decrypt a quad-dotted IPv4 address in place using format-preserving
// encryption. The key size is 8 bytes, and the buffer must have room for
// at least 16 bytes. Returns 1 on success or 0 if the input was invalid.
int
ipv4_decrypt(char *s, const void *key)
{
    long long r = ipv4_decode(s);
    if (r < 0) {
        return 0;
    }

    const unsigned char *p = key;
    unsigned long k0 = (unsigned long)p[0] <<  0 | (unsigned long)p[1] <<  8 |
                       (unsigned long)p[2] << 16 | (unsigned long)p[3] << 24;
    unsigned long k1 = (unsigned long)p[4] <<  0 | (unsigned long)p[5] <<  8 |
                       (unsigned long)p[6] << 16 | (unsigned long)p[7] << 24;

    unsigned long ip = r ^ k0 ^ k1;
    ip ^= ip >> 16;           ip *= 0xeb00ce77U; ip &= 0xffffffffU;
    ip ^= ip >> 16; ip -= k1; ip *= 0x88ccd46dU; ip &= 0xffffffffU;
    ip ^= ip >> 17; ip -= k0;
    ipv4_encode(s, ip & 0xffffffffU);
    return 1;
}


#ifdef TEST
// Usage:
//   $ cc -DTEST -O3 -fopenmp -o ipv4_crypt ipv4_crypt.c
//   $ printf '%s\n' 127.0.0.1 10.0.0.1 | ./ipv4_crypt
#include <stdio.h>
#include <string.h>

int
main(void)
{
    char buf[32];
    unsigned char key[8] = {0xab, 0xfc, 0x0d, 0x86, 0xea, 0x47, 0x56, 0xc5};

    while (fgets(buf, sizeof(buf), stdin)) {
        char *e = strchr(buf, '\n');
        if (e) *e = 0;

        int r = ipv4_encrypt(buf, key);
        if (!r) {
            puts("INVALID");
            continue;
        }

        printf("%s\t", buf);
        ipv4_decrypt(buf, key);
        puts(buf);
    }

    /* Test encode/decode */
    #pragma omp parallel for
    for (long long ip = 0; ip < 1LL<<32; ip++) {
        char want[16], got[16];
        sprintf(want, "%d.%d.%d.%d",
                (int)(ip >> 24 & 0xff), (int)(ip >> 16 & 0xff),
                (int)(ip >>  8 & 0xff), (int)(ip >>  0 & 0xff));
        ipv4_encode(got, ip);
        if (strcmp(want, got)) {
            printf("FAIL: (encode) %08llx, %s != %s\n", ip, want, got);
        }

        long long r = ipv4_decode(want);
        ipv4_encode(got, r);
        if (r != ip) {
            printf("FAIL: (decode) %08llx, %s != %s\n", ip, want, got);
        }
    }

    /* Test encrypt/decrypt */
    #pragma omp parallel for
    for (long long ip = 0; ip < 1LL<<32; ip++) {
        char want[16], got[16];
        ipv4_encode(want, ip);
        ipv4_encode(got, ip);
        ipv4_encrypt(got, key);
        ipv4_decrypt(got, key);
        if (strcmp(want, got)) {
            printf("FAIL: (encrypt) %08llx, %s != %s\n", ip, want, got);
        }
    }
}
#endif
