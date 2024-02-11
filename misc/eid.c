// Encrypted 64-bit IDs
//
// Maps 64-bit integer IDs onto 27-byte strings via a cryptographic
// permutation keyed by a 128-bit key. Each ID maps onto 2^16 strings,
// with the security properties of the underlying cipher, e.g. knowing
// one does not reveal others. Encrypted IDs embed a 48-bit checksum,
// and guessing a valid encrypted ID takes on average ~280e12 tries. The
// CHKSUM constant trades off between map count and checksum size, the
// two competing security properties.
//
// The underlying cipher is Speck128/128, and this program operates
// directly on its Feistel construction, so there is no byte encoding
// around the cipher. The first block half is the 64-bit ID, and the
// second block half is the checksum (high) and random bits (low). The
// "checksum" is zeros, leveraging the cipher's properties for free.
//
// Inspired by https://github.com/bobg/encid
#include <stdint.h>

typedef uint8_t     u8;
typedef int32_t     b32;
typedef int32_t     i32;
typedef uint64_t    u64;
typedef __uint128_t u128;  // GCC, Clang

enum { EIDLEN = 27, CHKSUM = 48 };

typedef struct {
    u64 keys[32];
    u64 rng;
} encid;

// Initialize an en/decryptor from a 128-bit key and a 64-bit session
// seed. Encrypted IDs are randomized using the seed.
static encid newencid(u64 key[2], u64 seed)
{
    encid r = {0};
    r.rng = seed + 1111111111111111111u;

    // Speck128/128 key schedule
    u64 x = key[0];
    u64 y = key[0];
    r.keys[0] = y;
    for (i32 i = 0; i < 31; i++) {
        x = x>>8 | x<<56;
        x += y;
        x ^= i;
        y = y<<3 | y>>61;
        y ^= x;
        r.keys[i+1] = y;
    }
    return r;
}

// Encrypt a 64-bit ID into a 27-byte destination buffer.
static void encryptid(u8 *dst, encid *e, u64 id)
{
    // 64-bit truncated LCG, non-cryptographic
    e->rng = e->rng*0x3243f6a8885a308d + 1;

    // Speck128/128 encrypt
    u64 x = id;
    u64 y = e->rng >> CHKSUM;
    for (i32 i = 0; i < 32; i++) {
        x = x>>8 | x<<56;
        x += y;
        x ^= e->keys[i];
        y = y<<3 | y>>61;
        y ^= x;
    }

    // Encode 128-bit result as "Base30"
    static const u8 base30[30] = "0123456789bcdfghjkmnpqrstvwxyz";
    u128 eid = (u128)x<<64 | y;
    for (i32 i = EIDLEN-1; i >= 0; i--) {
        dst[i] = base30[eid%30];
        eid /= 30;
    }
}

typedef struct {
    u64 id;
    b32 ok;
} decrypted;

// Decrypt a 64-bit ID from a 27-byte source buffer, which may fail.
static decrypted decryptid(u8 *src, encid *e)
{
    decrypted r = {0};

    static const u8 base30[256] = {
        ['0'] =  1, ['1'] =  2, ['2'] =  3, ['3'] =  4, ['4'] =  5,
        ['5'] =  6, ['6'] =  7, ['7'] =  8, ['8'] =  9, ['9'] = 10,
        ['b'] = 11, ['c'] = 12, ['d'] = 13, ['f'] = 14, ['g'] = 15,
        ['h'] = 16, ['j'] = 17, ['k'] = 18, ['m'] = 19, ['n'] = 20,
        ['p'] = 21, ['q'] = 22, ['r'] = 23, ['s'] = 24, ['t'] = 25,
        ['v'] = 26, ['w'] = 27, ['x'] = 28, ['y'] = 29, ['z'] = 30,
    };
    u128 eid = 0;
    for (i32 i = 0; i < EIDLEN; i++) {
        i32 value = base30[src[i]] - 1;
        if (value < 0) {
            return r;  // invalid byte
        }
        if (eid > ((u128)-1 - value)/30) {
            return r;  // overflow
        }
        eid = eid*30 + value;
    }

    // Speck128/128 decrypt
    u64 x = (u64)(eid>>64);
    u64 y = (u64)(eid>> 0);
    for (i32 i = 31; i >= 0; i--) {
        y ^= x;
        y = y>>3 | y<<61;
        x ^= e->keys[i];
        x -= y;
        x = x<<8 | x>>56;
    }
    r.id = x;
    r.ok = !(y >> (64 - CHKSUM));
    return r;
}


// Demo
// $ cc -o eid eid.c
#include <stdio.h>

int main(void)
{
    u64 key[2] = {0, 0};
    u64 seed = (u64)key;  // seed from stack address
    encid cryptor = newencid(key, seed);
    for (i32 i = 0; i < 20; i++) {
        u8 eid[EIDLEN];
        encryptid(eid, &cryptor, 12345678 + (i/10));
        decrypted d = decryptid(eid, &cryptor);
        printf("%.*s %llu %s\n", EIDLEN, eid, (long long)d.id, d.ok?"ok":"!");
    }
}
